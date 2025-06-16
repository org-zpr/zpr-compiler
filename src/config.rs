//! config.rs - load/parse a ZPL configuration TOML file

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;

use nix::NixPath;
use ring::digest::Digest;
use toml::Table;

use crate::context::CompilationCtx;
use crate::crypto::sha256;
use crate::errors::CompilationError;
use crate::protocols::{IanaProtocol, IcmpFlowType, Protocol, ZPR_L7_BUILTINS};
use crate::ptypes::Attribute;
use crate::zpl;

/// Helper to create a ConfigError. Works with a single string (or &str) argument
/// (really anything that has a to_string function), or with two args: a format string and arguments.
///
// TODO: Figure out how to put this in errors.rs
#[macro_export]
macro_rules! err_config {
    ($s:expr) => {
        CompilationError::ConfigError($s.to_string())
    };
    ($s:expr, $($arg:tt)*) => {
        CompilationError::ConfigError(format!($s, $($arg)*))
    };
}

/// Configuration structure which is parsed from the TOML.
#[allow(dead_code)]
pub struct Config {
    pub digest: Digest,
    resolver: Resolver,
    pub nodes: HashMap<String, Node>,
    pub visa_service: VisaService,
    pub bootstrap_cfg: Bootstrap,
    pub trusted_services: Vec<TrustedService>,
    pub protocols: HashMap<String, Protocol>,
    pub services: Vec<Service>,
}

/// ConfigParse holds state during a parse of the config toml.
struct ConfigParse {
    digest: Digest,
    ctoml: Table,
}

/// Service table
#[derive(Debug)]
pub struct Service {
    pub id: String,
    pub protocol_id: String, // Known protocol.  TODO: Could consider using a list here
    pub protocol_refinement: Option<ProtocolRefinement>, // optional protocol refinement
    pub provider: Option<Vec<(String, String)>>, // optional provider attributes
}

#[derive(Debug)]
pub struct ProtocolRefinement {
    pub port: Option<String>,       // override protocol port
    pub icmp: Option<IcmpFlowType>, // override protocol icmp (needed??)
}

impl ProtocolRefinement {
    pub fn apply(&self, protocol: &mut Protocol) {
        if let Some(refine) = &self.port {
            protocol.set_port(refine.clone());
        }
        if let Some(refine) = &self.icmp {
            protocol.set_icmp(refine.clone());
        }
    }
}

/// Resolver table.
#[allow(dead_code)]
#[derive(Debug)]
pub struct Resolver {
    pub order: Vec<String>,
    pub hosts: Option<HashMap<String, String>>,
}

impl Default for Resolver {
    fn default() -> Self {
        Resolver {
            order: vec!["hosts".to_string(), "dns".to_string()],
            hosts: None,
        }
    }
}

/// Node table.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub key: String,
    pub provider: Vec<(String, String)>,
    pub zpr_address: String,
    pub interfaces: Vec<Interface>,
}

/// Interface is part of a node.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub host: String, // host or IP
    pub port: u16,
}

/// Visa Service table ("visa_service")
#[allow(dead_code)]
#[derive(Debug)]
pub struct VisaService {
    pub dock_node_id: String,
}

pub struct Bootstrap {
    pub bootstraps: HashMap<String, PathBuf>, // CN -> public-key-pem-file
}

/// Trusted Service table ("trusted_services")
// TODO: Will these attribute descriptions need to be made more expressive so we can tell if they are optional, multi-valued, etc?
// TODO: Ports? Protocols?
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TrustedService {
    pub id: String,
    pub api: String,
    pub service: Option<String>, // Name of service for VS operations
    pub client: Option<String>,  // Name of service for client operations
    pub cert_path: Option<PathBuf>,
    pub returns_attrs: Vec<Attribute>,
    pub identity_attrs: Vec<Attribute>,
    pub provider: Option<Vec<(String, String)>>, // required for non-default
}

impl Config {
    /// Attempt to lookup the given hostname in the configurations resolver table.
    /// If the passed name does not map to an IP address, or if the name is not
    /// found in the table, then None is returned.
    pub fn resolve(&self, hostname: &str) -> Option<IpAddr> {
        // TODO: I suppose the resolver table could map a name to another name.
        //       For now that is not supported.
        self.resolver.hosts.as_ref()?.get(hostname)?.parse().ok()
    }
}

/// Parse and do some (light) error checking on the ZPL TOML configuration.
pub fn load_config(path: &Path, ctx: &CompilationCtx) -> Result<Config, CompilationError> {
    let cstr = std::fs::read_to_string(path).map_err(CompilationError::Io)?;
    parse_config(&cstr, ctx)
}

/// Parse config from the toml string `cstr`.
pub fn parse_config(cstr: &str, ctx: &CompilationCtx) -> Result<Config, CompilationError> {
    let mut parser = ConfigParse::new_from_toml_str(cstr)?;
    parser.parse(ctx)
}

impl ConfigParse {
    fn new_from_toml_str(cstr: &str) -> Result<ConfigParse, CompilationError> {
        let digest = sha256(cstr);

        let ctoml = cstr.parse::<Table>().map_err(CompilationError::TomlError)?;

        Ok(ConfigParse { digest, ctoml })
    }

    fn parse(&mut self, ctx: &CompilationCtx) -> Result<Config, CompilationError> {
        let resolver = self.parse_resolver()?;
        let nodes = self.parse_nodes()?;
        let visa_service = self.parse_visa_service(ctx)?;
        let bootstrap = self.parse_bootstrap(ctx)?;
        let trusted_services = self.parse_trusted_services(ctx)?;
        let mut protocols = self.parse_protocols(ctx)?;
        self.add_default_protocols(&mut protocols);
        let services = self.parse_services(ctx, &protocols)?;
        Ok(Config {
            digest: self.digest,
            resolver,
            nodes,
            visa_service,
            bootstrap_cfg: bootstrap,
            trusted_services,
            protocols,
            services,
        })
    }

    // Note that these are added with their default ports.
    fn add_default_protocols(&self, protocols: &mut HashMap<String, Protocol>) {
        for pname in ZPR_L7_BUILTINS {
            protocols.insert(
                pname.to_string(),
                Protocol::new_zpr(pname.to_string(), pname.to_string(), None).unwrap(),
            );
        }
    }

    /// Parse the resolver section which is optional.  The defualt is just
    /// to have an `resolver.order` set to [hosts, dns].  The hosts section is optional, but
    /// if present is mapping of hostnames to IP addresses.
    fn parse_resolver(&self) -> Result<Resolver, CompilationError> {
        if !self.ctoml.contains_key("resolver") {
            return Ok(Resolver::default());
        }
        let r = self.ctoml["resolver"]
            .as_table()
            .ok_or(err_config!("error reading resolver section"))?;
        let mut order_vec = Vec::new();
        if !r.contains_key("order") {
            // Default order is hosts, dns
            order_vec.push("hosts".to_string());
            order_vec.push("dns".to_string());
        } else {
            let order = r["order"]
                .as_array()
                .ok_or(err_config!("resolver.order must be an array"))?;
            for o in order {
                order_vec.push(
                    o.as_str()
                        .ok_or(err_config!("problem with order array"))?
                        .to_string(),
                );
            }
        }

        let hosts = if r.contains_key("hosts") {
            match r["hosts"].as_table() {
                Some(h) => {
                    let mut hosts_map = HashMap::new();
                    for (k, v) in h {
                        hosts_map.insert(
                            k.to_string(),
                            v.as_str()
                                .ok_or(CompilationError::ConfigError(format!(
                                    "invalid hosts entry {}",
                                    k
                                )))?
                                .to_string(),
                        );
                    }
                    Some(hosts_map)
                }
                None => None,
            }
        } else {
            None
        };

        Ok(Resolver {
            order: order_vec,
            hosts,
        })
    }

    /// Parse all the nodes.<ID> sections. There must be at least one.
    fn parse_nodes(&self) -> Result<HashMap<String, Node>, CompilationError> {
        if !self.ctoml.contains_key("nodes") {
            return Err(err_config!("missing section: nodes"));
        }
        let nodes = self.ctoml["nodes"]
            .as_table()
            .ok_or(err_config!("error reading nodes section"))?;
        // Within "nodes" each KEY is a node ID that is a table.
        let mut node_map = HashMap::new();
        for (node_id, v) in nodes {
            let n = parse_node(
                node_id,
                v.as_table()
                    .ok_or(err_config!("node {} is not a table", node_id))?,
            )?;
            node_map.insert(node_id.to_string(), n);
        }
        Ok(node_map)
    }

    /// Parse the very basic visa_service section.
    fn parse_visa_service(
        &mut self,
        _ctx: &CompilationCtx,
    ) -> Result<VisaService, CompilationError> {
        if !self.ctoml.contains_key("visa_service") {
            return Err(err_config!("missing section: visa_service"));
        }
        let vs = self.ctoml["visa_service"]
            .as_table()
            .ok_or(err_config!("error reading visa_service section"))?;
        if !vs.contains_key("dock_node") {
            return Err(err_config!("visa_service missing dock_node"));
        }
        let dock_node_id = vs["dock_node"]
            .as_str()
            .ok_or(err_config!("visa_service missing dock_node"))?
            .to_string();

        Ok(VisaService { dock_node_id })
    }

    // Parse optional boostrap section. Each entry in the table is of the form: `<CN> = <KEYFILE>`.
    fn parse_bootstrap(&mut self, _ctx: &CompilationCtx) -> Result<Bootstrap, CompilationError> {
        let mut bootstraps = HashMap::new();

        if !self.ctoml.contains_key("bootstrap") {
            return Ok(Bootstrap {
                bootstraps, // empty
            });
        }

        let vs = self.ctoml["bootstrap"]
            .as_table()
            .ok_or(err_config!("error reading bootstrap section"))?;

        // Each entry in our map is expected to be a CN name and a path to a PEM file.
        for (cn, v) in vs {
            let v = v
                .as_str()
                .ok_or(err_config!("bootstrap path for {} is not a string", cn))?;
            let path = PathBuf::from(v);
            if path.is_empty() {
                return Err(err_config!("bootstrap path for {} is empty", cn));
            }
            // TODO: Need to fix path if not absolute.
            bootstraps.insert(cn.to_string(), path);
        }
        Ok(Bootstrap { bootstraps })
    }

    /// Parse the trusted_services.<ID> tables.  Currently I am reserving the ID of "default" for the
    /// sort of built-in certificate authority based authentication mechanism.
    fn parse_trusted_services(
        &mut self,
        ctx: &CompilationCtx,
    ) -> Result<Vec<TrustedService>, CompilationError> {
        if !self.ctoml.contains_key("trusted_services") {
            ctx.warn("no trusted services in configuration")?;
            return Ok(Vec::new());
        }
        let ts = self.ctoml["trusted_services"]
            .as_table()
            .ok_or(err_config!("error reading trusted_services section"))?;
        let mut trusted_services = Vec::new();
        for (ts_id, v) in ts {
            let ts = parse_trusted_service(
                ts_id,
                v.as_table()
                    .ok_or(err_config!("trusted_service {} is not a table", ts_id))?,
            )?;
            trusted_services.push(ts);
        }
        Ok(trusted_services)
    }

    /// Parse the protocols.<ID> tables.
    fn parse_protocols(
        &mut self,
        ctx: &CompilationCtx,
    ) -> Result<HashMap<String, Protocol>, CompilationError> {
        if !self.ctoml.contains_key("protocols") {
            ctx.warn("no protocols in configuration")?;
            return Ok(HashMap::new());
        }
        let prots = self.ctoml["protocols"]
            .as_table()
            .ok_or(err_config!("error reading protocols section"))?;
        let mut protocols = HashMap::new();
        for (prot_id, v) in prots {
            if protocols.contains_key(prot_id) {
                return Err(err_config!("duplicate protocol id: {}", prot_id));
            }
            let prot = parse_protocol(
                prot_id,
                v.as_table()
                    .ok_or(err_config!("protocol {} is not a table", prot_id))?,
            )?;
            protocols.insert(prot_id.to_string(), prot);
        }
        Ok(protocols)
    }

    /// Parse the services.<ID> tables
    fn parse_services(
        &mut self,
        ctx: &CompilationCtx,
        protocols: &HashMap<String, Protocol>,
    ) -> Result<Vec<Service>, CompilationError> {
        if !self.ctoml.contains_key("services") {
            ctx.warn("no services in configuration")?;
            return Ok(Vec::new());
        }
        let services = self.ctoml["services"]
            .as_table()
            .ok_or(err_config!("error reading services section"))?;
        let mut ret = Vec::new();
        for (sid, v) in services {
            let s = parse_service(
                sid,
                v.as_table()
                    .ok_or(err_config!("service {} is not a table", sid))?,
                protocols,
            )?;
            ret.push(s);
        }
        Ok(ret)
    }
}

fn require_key(ctx: &str, table: &Table, key: &str) -> Result<(), CompilationError> {
    if !table.contains_key(key) {
        return Err(err_config!("error in {}: missing entry for {}", ctx, key));
    }
    Ok(())
}

/// Parse a single node table.
fn parse_node(node_id: &str, node: &Table) -> Result<Node, CompilationError> {
    require_key(&format!("nodes.{}", node_id), node, "key")?;
    let key = node["key"]
        .as_str()
        .ok_or(err_config!("node {} missing key", node_id))?
        .to_string();
    require_key(&format!("nodes.{}", node_id), node, "zpr_address")?;
    let zpr_address = node["zpr_address"]
        .as_str()
        .ok_or(err_config!("node {} invalid zpr_address", node_id))?
        .to_string();

    let mut interfaces = Vec::new();

    // In order to parse the interfaces, we need the interface names.
    require_key(&format!("node {}", node_id), node, "interfaces")?;
    let ifnames = node["interfaces"]
        .as_array()
        .ok_or(err_config!("node {} missing interfaces", node_id))?;
    for ifname in ifnames {
        let ifname = ifname.as_str().ok_or(err_config!(
            "node {} interface name is not a string",
            node_id
        ))?;

        // The node contains a table entry for each interface name.
        if !node.contains_key(ifname) {
            return Err(err_config!(
                "node {} missing entry for interface {}",
                node_id,
                ifname
            ));
        }
        let iface = parse_interface(
            ifname,
            node[ifname].as_table().ok_or(err_config!(
                "node {} interface {} is not a table",
                node_id,
                ifname
            ))?,
        )?;
        interfaces.push(iface);
    }

    let provider = parse_provider(&format!("node {}", node_id), node)?;

    Ok(Node {
        id: node_id.to_string(),
        key,
        zpr_address,
        interfaces,
        provider,
    })
}

fn parse_provider(ctx: &str, table: &Table) -> Result<Vec<(String, String)>, CompilationError> {
    // The provider is an array of tuples (array of arrays).
    if !table.contains_key("provider") {
        return Err(err_config!("{} missing provider", ctx));
    }
    let provider_tuples = table["provider"]
        .as_array()
        .ok_or(err_config!("{} provider is not an array", ctx))?;

    let provider = tuples_to_tuple_str_vec(ctx, provider_tuples)?;
    Ok(provider)
}

/// Parse the nodes interface entry.
fn parse_interface(ifname: &str, iface: &Table) -> Result<Interface, CompilationError> {
    if !iface.contains_key("netaddr") {
        return Err(err_config!("interface {} missing netaddr", ifname));
    }
    let netaddr = iface["netaddr"]
        .as_str()
        .ok_or(err_config!("interface {} missing netaddr", ifname))?
        .to_string();

    // Form of `netaddr` is HOST:PORT, host may be a hostname (which may need to be run through the resolver)
    // or an IPv4 or IPv6 address.

    // We'll try to parse as a SocketAddr first (which requires an IP address, not a name)
    //let saddr: std::net::SocketAddr = netaddr.parse();
    match netaddr.parse::<std::net::SocketAddr>() {
        Ok(saddr) => Ok(Interface {
            name: ifname.to_string(),
            host: saddr.ip().to_string(),
            port: saddr.port(),
        }),
        Err(_) => {
            // Did not parse as a SocketAddr, so try as "hostname:portnum"
            let parts: Vec<&str> = netaddr.split(':').collect();
            if parts.len() != 2 {
                return Err(err_config!(
                    "interface {} netaddr must be in the form HOST:PORT",
                    ifname
                ));
            }
            let portnum = parts[1].parse::<u16>().map_err(|_| {
                err_config!(
                    "interface {} port number is not a valid: {}",
                    ifname,
                    parts[1]
                )
            })?;
            Ok(Interface {
                name: ifname.to_string(),
                host: parts[0].to_string(),
                port: portnum,
            })
        }
    }
}

fn tuples_to_tuple_str_vec(
    ctx: &str,
    tuples: &Vec<toml::Value>,
) -> Result<Vec<(String, String)>, CompilationError> {
    let mut svec = Vec::new();
    for pt in tuples {
        let pt = pt
            .as_array()
            .ok_or(err_config!("{} has entry that is not an array", ctx))?;
        if pt.len() != 2 {
            return Err(err_config!("{} has entry is not a 2-tuple", ctx));
        }
        // TOML has other valid types but we just convert the provider attributes to strings.
        // Maybe later we will introduce a richer attribute type since we are probably going to have to parse this again later.
        let p0 = if pt[0].is_str() {
            pt[0].as_str().unwrap().to_string()
        } else {
            pt[0].to_string()
        };
        let p1 = if pt[1].is_str() {
            pt[1].as_str().unwrap().to_string()
        } else {
            pt[1].to_string()
        };
        svec.push((p0, p1));
    }
    Ok(svec)
}

// Parse an individual trusted_service table.
fn parse_trusted_service(ts_id: &str, ts: &Table) -> Result<TrustedService, CompilationError> {
    // The "api" value is optional for the default trusted service.
    let mut is_default = false;
    let api = if ts.contains_key("api") {
        ts["api"]
            .as_str()
            .ok_or(err_config!("trusted_service {} missing api", ts_id))?
            .to_string()
    } else if ts_id == zpl::DEFAULT_TRUSTED_SERVICE_ID {
        is_default = true;
        zpl::DEFAULT_TRUSTED_SERVICE_API.to_string()
    } else {
        return Err(err_config!("trusted_service {} missing api", ts_id));
    };
    let cert_path = if ts.contains_key("cert_path") {
        Some(PathBuf::from(ts["cert_path"].as_str().ok_or(
            err_config!("trusted_service {} cert_path is not a string", ts_id),
        )?))
    } else if is_default {
        // The path is the only thing required for the default section.
        return Err(err_config!("default trusted_service requires cert_path"));
    } else {
        None
    };
    let returns_attrs: Vec<String>;
    let identity_attrs: Vec<String>;
    let client_svc: Option<String>;
    let service_svc: Option<String>;
    if !is_default {
        returns_attrs = parse_string_array(ts, "returns_attributes", "trusted_service")?;
        identity_attrs = parse_string_array(ts, "identity_attributes", "trusted_service")?;
        check_attr_keys_domain_and_uniqueness(ts_id, &returns_attrs, &identity_attrs)?;

        // Identity attributes (if any) must be listed in returns attributes
        for ia in &identity_attrs {
            if !returns_attrs.contains(ia) {
                return Err(err_config!(
                    "trusted_service {} identity attribute '{}' not in returns_attributes",
                    ts_id,
                    ia
                ));
            }
        }
        if ts.contains_key("client") {
            client_svc = Some(
                ts["client"]
                    .as_str()
                    .ok_or(err_config!("trusted_service {} client parse error", ts_id))?
                    .to_string(),
            );
        } else {
            client_svc = Some(format!("{}-client", ts_id));
        }
        if ts.contains_key("service") {
            service_svc = Some(
                ts["service"]
                    .as_str()
                    .ok_or(err_config!("trusted_service {} service parse error", ts_id))?
                    .to_string(),
            );
        } else {
            service_svc = Some(format!("{}-vs", ts_id));
        }
    } else {
        if ts.contains_key("returns_attributes") {
            return Err(err_config!(
                "default trusted_service does not allow custom returns_attributes"
            ));
        }
        if ts.contains_key("identity_attributes") {
            return Err(err_config!(
                "default trusted_service does not allow custom identity_attributes"
            ));
        }
        returns_attrs = vec![String::from(zpl::KATTR_CN)];
        identity_attrs = vec![String::from(zpl::KATTR_CN)];
        client_svc = None;
        service_svc = None;
    }

    // We have a simple way to specify tags in the config toml: prefix name with hash '#'.
    // TODO: Need a notation for multi-valued attributes.

    let mut returns = Vec::new();
    for ra in &returns_attrs {
        if let Some(stripped) = ra.strip_prefix("#") {
            returns.push(Attribute::tag(stripped)?);
        } else {
            returns.push(Attribute::attr_name_only(ra)?);
        }
    }

    let mut idents = Vec::new();
    for ra in &identity_attrs {
        if ra.starts_with("#") {
            return Err(err_config!("identity attribute cannot be a tag: '{}'", ra));
        }
        idents.push(Attribute::attr_name_only(ra)?);
    }

    let provider = if ts.contains_key("provider") {
        Some(parse_provider(&format!("trusted_service {ts_id}"), ts)?)
    } else {
        if !is_default {
            return Err(err_config!("trusted_service {} missing provider", ts_id));
        }
        None
    };

    Ok(TrustedService {
        id: ts_id.to_string(),
        api,
        cert_path,
        returns_attrs: returns,
        identity_attrs: idents,
        provider,
        client: client_svc,
        service: service_svc,
    })
}

/// Parse table entry `key` as a string array.  If key is not found returns empty vector.
fn parse_string_array(ts: &Table, key: &str, ctx: &str) -> Result<Vec<String>, CompilationError> {
    if !ts.contains_key(key) {
        return Ok(Vec::new());
    }
    let arr = ts[key]
        .as_array()
        .ok_or(err_config!("{} {} is not an array", ctx, key))?;
    let mut ret = Vec::new();
    for a in arr {
        ret.push(
            a.as_str()
                .ok_or(err_config!("{} {} array entry is not a string", ctx, key))?
                .to_string(),
        );
    }
    Ok(ret)
}

/// Every attribute needs to be in a domain which is indicated the the ZPL configuration.
/// When we talk to trusted services we only get back the key parts without any domain.
/// So in order to map the returned keys to the correct domain we require that all the keys
/// are unique.  So you cannot have attributes in different domains with the same key.
/// For exmaple this is not allowed: ["device.id", "user.id"].
fn check_attr_keys_domain_and_uniqueness(
    ts_id: &str,
    returns_attrs: &[String],
    identity_attrs: &[String],
) -> Result<(), CompilationError> {
    // Gather all the attributes without regard to wehether they are in the returns or identity attributes.
    let mut uniq_attrs = HashSet::<&str>::new();
    for attr_list in [returns_attrs, identity_attrs] {
        for attr in attr_list {
            uniq_attrs.insert(attr);
        }
    }

    let mut uniq_keys = HashSet::<String>::new();

    for attr in &uniq_attrs {
        // The attrs in a config may have a special char '#' on the front to indicate a tag.
        // We strip that off.
        let attr = if attr.starts_with('#') {
            &attr[1..]
        } else {
            attr
        };
        match Attribute::parse_domain(attr) {
            Ok((_domain, key)) => {
                if uniq_keys.contains(&key) {
                    return Err(err_config!(
                        "trusted_service {} attribute '{}' uses key '{}' which is not unique",
                        ts_id,
                        attr,
                        key
                    ));
                }
                uniq_keys.insert(key);
            }
            Err(_) => {
                return Err(err_config!(
                    "trusted_service {} attribute '{}' is not in a valid domain",
                    ts_id,
                    attr,
                ));
            }
        }
    }
    Ok(())
}

/// Parse an individual protocol table.
/// Allow fields are:
/// - l4protocol (iana protocol name)
/// - 7lprotocol (app layer protocol name eg, HTTP or a ZPR protocol name)
/// - port (optional)
/// - icmp_type
/// - icmp_codes
fn parse_protocol(prot_label: &str, prot: &Table) -> Result<Protocol, CompilationError> {
    if !prot.contains_key("l4protocol") {
        return Err(err_config!(
            "protocol {} missing key 'l4protocol'",
            prot_label
        ));
    }
    let protocol_name = prot["l4protocol"]
        .as_str()
        .ok_or(err_config!("protocol {} missing protocol", prot_label))?
        .to_string();
    let is_icmp = prot.contains_key("icmp_type") || prot.contains_key("icmp_codes");
    let (port, icmp) = parse_port_and_or_icmp(prot_label, is_icmp, prot)?;
    let l7protocol = if prot.contains_key("l7protocol") {
        Some(
            prot["l7protocol"]
                .as_str()
                .ok_or(err_config!(
                    "protocol {} l7protocol is not a string",
                    prot_label
                ))?
                .to_string(),
        )
    } else {
        None
    };
    if let Some(l4) = IanaProtocol::parse(&protocol_name) {
        Ok(Protocol::new(
            prot_label.to_string(),
            l4,
            port,
            icmp,
            l7protocol,
        ))
    } else {
        Err(err_config!(
            "protocol {}: invalid l4 protocol name: {}",
            prot_label,
            protocol_name
        ))
    }
}

fn parse_port_and_or_icmp(
    ctx: &str,
    is_icmp: bool,
    prot: &Table,
) -> Result<(Option<String>, Option<IcmpFlowType>), CompilationError> {
    // For now we treat the port value as a string. But is really going to be a port spec so could
    // be a range of ports or a sequence of ports, etc.  In TOML this may come through as a number.
    let port = if prot.contains_key("port") {
        if prot["port"].is_str() {
            Some(prot["port"].as_str().unwrap().to_string())
        } else {
            Some(prot["port"].to_string())
        }
    } else {
        None
    };

    let icmp = if is_icmp {
        Some(parse_icmp_details(ctx, prot)?)
    } else {
        if prot.contains_key("icmp_type") {
            return Err(err_config!(
                "protocol {} has icmp_type but is not an ICMP protocol",
                ctx
            ));
        }
        if prot.contains_key("icmp_codes") {
            return Err(err_config!(
                "protocol {} has icmp_codes but is not an ICMP protocol",
                ctx,
            ));
        }
        None
    };

    Ok((port, icmp))
}

/// Parse the very bare bones individual service table.
///
/// A service must reference a defined protocol using the `protocol` key, it can also
/// additionally override a port or icmp setting in a defined protocol.
fn parse_service(
    sid: &str,
    s: &Table,
    protocols: &HashMap<String, Protocol>,
) -> Result<Service, CompilationError> {
    if !s.contains_key("protocol") {
        return Err(err_config!("service {} missing protocol", sid));
    }
    let protocol_label = s["protocol"]
        .as_str()
        .ok_or(err_config!("service {} missing protocol", sid))?
        .to_string();
    let provider = if s.contains_key("provider") {
        Some(parse_provider(&format!("service {}", sid), s)?)
    } else {
        None
    };

    let Some(matched_protocol) = protocols.get(&protocol_label) else {
        return Err(err_config!(
            "service {} references unknown protocol {}",
            sid,
            protocol_label
        ));
    };

    // The service could contain overrides for protocol.
    let looks_like_icmp = s.contains_key("icmp_type") || s.contains_key("icmp_codes");
    let (port, icmp) = parse_port_and_or_icmp(sid, looks_like_icmp, s)?;
    let opt_refine =
        // Is in our table.  Did this clause specify any sort of override?
        if port.is_some() || icmp.is_some() {
            if port.is_some() && matched_protocol.is_icmp() {
                return Err(err_config!(
                    "service {}: cannot override port for ICMP protocol: {}",
                    sid,
                    protocol_label
                ));
            }
            if icmp.is_some() && !matched_protocol.is_icmp() {
                return Err(err_config!(
                    "service {}: cannot override icmp for non-ICMP protocol: {}",
                    sid,
                    protocol_label
                ));
            }
            let refinement = ProtocolRefinement {
                port,
                icmp,
            };
            Some(refinement)
        } else {
            // No override, just use the protocol as is.
            None
        };

    Ok(Service {
        id: sid.to_string(),
        protocol_id: protocol_label,
        protocol_refinement: opt_refine,
        provider,
    })
}

/// Parse and do light error checking on the ICMP details (the icmp_type and icmp_codes).
fn parse_icmp_details(prot_id: &str, prot: &Table) -> Result<IcmpFlowType, CompilationError> {
    if !prot.contains_key("icmp_type") {
        return Err(err_config!("protocol {} missing icmp_type", prot_id));
    }
    if !prot.contains_key("icmp_codes") {
        return Err(err_config!("protocol {} missing icmp_codes", prot_id));
    }

    let codes = prot["icmp_codes"].as_array().ok_or(err_config!(
        "protocol {} icmp_codes is not an array",
        prot_id
    ))?;
    if codes.is_empty() {
        return Err(err_config!("protocol {} icmp_codes is empty", prot_id));
    }

    let ft = prot["icmp_type"]
        .as_str()
        .ok_or(err_config!("protocol {} icmp missing interaction", prot_id))?
        .to_string()
        .to_lowercase();

    let interaction: IcmpFlowType;

    if ft == zpl::ICMP_INTERACION_REQUEST_RESPONSE {
        if codes.len() != 2 {
            return Err(err_config!(
                "protocol {} icmp request-response requires exactly two type codes",
                prot_id
            ));
        }
        let code0 = toml_as_u8(&codes[0])
            .ok_or(err_config!("protocol {} icmp code[0] invalid", prot_id))?;
        let code1 = toml_as_u8(&codes[1])
            .ok_or(err_config!("protocol {} icmp code[1] invalid", prot_id))?;
        interaction = IcmpFlowType::RequestResponse(code0, code1);
    } else if ft == zpl::ICMP_INTERACTION_ONESHOT {
        let mut parsed_codes = Vec::new();
        for tcode in codes {
            let code = toml_as_u8(tcode).ok_or(err_config!(
                "protocol {} icmp code '{}' is invalid",
                prot_id,
                tcode
            ))?;
            parsed_codes.push(code);
        }
        interaction = IcmpFlowType::OneShot(parsed_codes);
    } else {
        return Err(err_config!(
            "protocol {} invalid icmp interaction type: {}",
            prot_id,
            ft
        ));
    }

    Ok(interaction)
}

/// Convert a TOML integer to a u8.  Returns None if the integer is out of range.
fn toml_as_u8(v: &toml::Value) -> Option<u8> {
    match v {
        toml::Value::Integer(i) if *i >= 0 && *i <= 255 => Some(*i as u8),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_resolver_empty() {
        let tstr = r#"
        [resolver]
        "#;
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let r = cparser.parse_resolver();
        assert!(r.is_ok());
        let r = r.unwrap();
        assert_eq!(r.order.len(), 2);
        assert!(r.order.contains(&"hosts".to_string()));
        assert!(r.order.contains(&"dns".to_string()));
        assert!(r.hosts.is_none());
    }

    #[test]
    fn test_parse_resolver_data() {
        let tstr = r#"
        [resolver]
        order = ["dns", "hosts", "foo"]
        [resolver.hosts]
        "n0" = "1.2.3.4"
        "n1.foo" = "5.6.7.8"
        "#;
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let r = cparser.parse_resolver();
        assert!(r.is_ok());
        let r = r.unwrap();
        assert_eq!(r.order.len(), 3);
        assert!(r.order.contains(&"dns".to_string()));
        assert!(r.order.contains(&"hosts".to_string()));
        assert!(r.order.contains(&"foo".to_string()));
        assert!(r.hosts.is_some());
        let hosts = r.hosts.unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts.get("n0").unwrap(), "1.2.3.4");
        assert_eq!(hosts.get("n1.foo").unwrap(), "5.6.7.8");
    }

    #[test]
    fn test_parse_node() {
        let tstr = r#"
        [nodes]
        [nodes.n0]
        key = "somekey"
        zpr_address = "foo.zpr"
        provider = [["zpr.foo", "bar"], ["baz", 99]]
        interfaces = ["eth0", "eth1"]
        eth0.netaddr = "1.2.3.4:2000"
        eth1.netaddr = "foo.addr:9000"
        "#;
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let nodes = cparser.parse_nodes();
        assert!(nodes.is_ok(), "{:?}", nodes);
        let nodes = nodes.unwrap();
        assert_eq!(nodes.len(), 1);
        let n0 = nodes.get("n0").unwrap();
        assert_eq!(n0.id, "n0");
        assert_eq!(n0.key, "somekey");
        assert_eq!(n0.zpr_address, "foo.zpr");
        assert_eq!(n0.interfaces.len(), 2);
        for iface in &n0.interfaces {
            match iface.name.as_str() {
                "eth0" => {
                    assert_eq!(iface.host, "1.2.3.4");
                    assert_eq!(iface.port, 2000);
                }
                "eth1" => {
                    assert_eq!(iface.host, "foo.addr");
                    assert_eq!(iface.port, 9000);
                }
                _ => panic!("unexpected interface name"),
            }
        }
        assert_eq!(n0.provider.len(), 2);
        assert!(n0
            .provider
            .contains(&("zpr.foo".to_string(), "bar".to_string())));
        assert!(n0.provider.contains(&("baz".to_string(), "99".to_string())));
    }

    #[test]
    fn test_parse_visa_service() {
        let tstr = r#"
        [visa_service]
        dock_node = "n0"
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let vs = cparser.parse_visa_service(&ctx);
        assert!(vs.is_ok());
        let vs = vs.unwrap();
        assert_eq!(vs.dock_node_id, "n0");
    }

    #[test]
    fn test_parse_trusted_service_default() {
        let tstr = r#"
        [trusted_services.default]
        cert_path = "foo.pem"
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let services = cparser.parse_trusted_services(&ctx);
        assert!(
            services.is_ok(),
            "parse failed: {:?}",
            services.unwrap_err()
        );
        let services = services.unwrap();
        assert_eq!(services.len(), 1);
        let ts = services.get(0).unwrap();
        assert_eq!(ts.id, "default");
        assert_eq!(ts.api, zpl::DEFAULT_TRUSTED_SERVICE_API);
        assert_eq!(ts.cert_path, Some(PathBuf::from("foo.pem")));
        assert_eq!(ts.returns_attrs.len(), 1);
        assert_eq!(ts.returns_attrs[0].zpl_key(), "device.zpr.adapter.cn");
        assert_eq!(ts.identity_attrs.len(), 1);
        assert_eq!(ts.identity_attrs[0].zpl_key(), "device.zpr.adapter.cn");
    }

    #[test]
    fn test_parse_trusted_service_other() {
        // missing api fails
        let tstr = r#"
        [trusted_services.other]
        cert_path = "foo.pem"
        prefix = "bar.hop"
        returns_attributes = ["user.a", "user.c"]
        identity_attributes = ["user.c"]
        provider = [["foo", "bar"]]
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let services = cparser.parse_trusted_services(&ctx);
        let err = services.unwrap_err();
        assert!(
            err.to_string().contains("missing api"),
            "expected error about missing api, got: {}",
            err
        );

        // and with api succeeds
        let tstr = r#"
        [trusted_services.other]
        api = "validation/2"
        cert_path = "foo.pem"
        prefix = "bar.hop"
        returns_attributes = ["user.a", "user.c"]
        identity_attributes = ["user.c"]
        provider = [["foo", "bar"]]
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let services = cparser.parse_trusted_services(&ctx);
        if services.is_err() {
            panic!("parse_trusted_services failed: {:?}", services);
        }
        assert!(services.is_ok());
        let services = services.unwrap();
        assert_eq!(services.len(), 1);
        let ts = services.get(0).unwrap();
        assert_eq!(ts.id, "other");
        assert_eq!(ts.api, "validation/2");
        assert_eq!(ts.cert_path, Some(PathBuf::from("foo.pem")));
        assert_eq!(ts.returns_attrs.len(), 2);
        {
            let attr_names = ts
                .returns_attrs
                .iter()
                .map(|a| a.zpl_key())
                .collect::<Vec<String>>();
            assert!(attr_names.contains(&"user.a".to_string()));
            assert!(attr_names.contains(&"user.c".to_string()));
        }
        assert_eq!(ts.identity_attrs.len(), 1);
        assert!(ts.identity_attrs[0].zpl_key() == "user.c");
    }

    #[test]
    fn test_parse_trusted_service_unique_keys() {
        // Should fail because we have duplicate keys (even though different namespaces)
        let tstr = r##"
        [trusted_services.other]
        api = "validation/2"
        cert_path = "foo.pem"
        prefix = "bar.hop"
        returns_attributes = ["user.foo", "user.fee", "#device.foo"]
        identity_attributes = ["user.foo"]
        provider = [["foo", "bar"]]
        "##;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let services = cparser.parse_trusted_services(&ctx);
        assert!(services.is_err());
        // check that error message contains the duplicate key
        if let Err(e) = services {
            assert!(
                e.to_string().contains("which is not unique"),
                "expected error about non-unique key, got: {}",
                e
            );
        } else {
            panic!("parse_trusted_services should have failed");
        }
    }

    #[test]
    fn test_parse_trusted_service_prefix_not_required() {
        let tstr = r#"
        [trusted_services.other]
        api = "validation/2"
        cert_path = "foo.pem"
        returns_attributes = ["user.a", "user.c"]
        identity_attributes = ["user.c"]
        provider = [["foo", "bar"]]
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let services = cparser.parse_trusted_services(&ctx);
        if services.is_err() {
            panic!("parse_trusted_services failed: {:?}", services);
        }
        assert!(services.is_ok());
        let services = services.unwrap();
        assert_eq!(services.len(), 1);
        let ts = services.get(0).unwrap();
        assert_eq!(ts.id, "other");
        assert_eq!(ts.api, "validation/2");
        assert_eq!(ts.cert_path, Some(PathBuf::from("foo.pem")));
        assert_eq!(ts.returns_attrs.len(), 2);
        {
            let attr_names = ts
                .returns_attrs
                .iter()
                .map(|a| a.zpl_key())
                .collect::<Vec<String>>();
            assert!(attr_names.contains(&"user.a".to_string()));
            assert!(attr_names.contains(&"user.c".to_string()));
        }
        assert_eq!(ts.identity_attrs.len(), 1);
        assert!(ts.identity_attrs[0].zpl_key() == "user.c");
        assert_eq!(ts.client, Some("other-client".to_string()));
        assert_eq!(ts.service, Some("other-vs".to_string()));
    }

    #[test]
    fn test_parse_trusted_service_bas() {
        let tstr = r#"
        [trusted_services.bas]
        api = "validation/2"
        cert_path = "foo.crt"
        returns_attributes = ["user.a", "user.c"]
        identity_attributes = ["user.c"]
        provider = [["foo", "bar"]]
        client = "bas-client-interface"
        service = "bas-vs-interface"
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let services = cparser.parse_trusted_services(&ctx);
        assert!(services.is_ok());
        let services = services.unwrap();
        assert_eq!(services.len(), 1);
        let ts = services.get(0).unwrap();
        assert_eq!(ts.id, "bas");
        assert_eq!(ts.api, "validation/2");
        assert_eq!(ts.cert_path, Some(PathBuf::from("foo.crt")));
        assert!(ts.provider.is_some());
        let provider = ts.provider.as_ref().unwrap();
        assert_eq!(provider.len(), 1);
        assert!(provider.contains(&("foo".to_string(), "bar".to_string())));
        assert_eq!(ts.returns_attrs.len(), 2);
        {
            let attr_names = ts
                .returns_attrs
                .iter()
                .map(|a| a.zpl_key())
                .collect::<Vec<String>>();
            assert!(attr_names.contains(&"user.a".to_string()));
            assert!(attr_names.contains(&"user.c".to_string()));
        }
        assert_eq!(ts.identity_attrs.len(), 1);
        assert!(ts.identity_attrs[0].zpl_key() == "user.c");
        assert_eq!(ts.client, Some("bas-client-interface".to_string()));
        assert_eq!(ts.service, Some("bas-vs-interface".to_string()));
    }

    #[test]
    fn test_parse_protocols() {
        let tstr = r#"
        [protocols.http]
        l4protocol = "iana.Tcp"
        port = "80"

        [protocols.ping]
        l4protocol = "iana.ICMP6"
        icmp_type = "request-response"
        icmp_codes = [128, 129]
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let prots = cparser.parse_protocols(&ctx);
        assert!(prots.is_ok());
        let prots = prots.unwrap();
        assert_eq!(prots.len(), 2);
        let http = prots.get("http").unwrap();
        assert_eq!(http.get_layer4(), IanaProtocol::TCP);
        assert_eq!(http.get_port(), Some(&String::from("80")));
        assert!(!http.is_icmp());
        let ping = prots.get("ping").unwrap();
        assert_eq!(ping.get_layer4(), IanaProtocol::ICMPv6);
        assert!(!ping.has_port());
        let icmp = ping.get_icmp().unwrap();
        match icmp {
            IcmpFlowType::RequestResponse(c0, c1) => {
                assert_eq!(*c0, 128);
                assert_eq!(*c1, 129);
            }
            _ => panic!("unexpected icmp type"),
        }
    }

    #[test]
    fn test_parse_services() {
        let tstr = r#"
        [services.MyService]
        protocol = "ping"

        [services.MyOtherService]
        protocol = "pong"
        provider = [["foo", "bar"]]
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let mut protocols = HashMap::new();
        protocols.insert(
            String::from("ping"),
            Protocol::new("ping".to_string(), IanaProtocol::ICMPv6, None, None, None),
        );
        protocols.insert(
            String::from("pong"),
            Protocol::new("pong".to_string(), IanaProtocol::ICMPv6, None, None, None),
        );
        let services = cparser.parse_services(&ctx, &protocols);
        if services.is_err() {
            panic!("parse_services failed: {:?}", services);
        }
        assert!(services.is_ok());
        let services = services.unwrap();
        assert_eq!(services.len(), 2);
        let mut hits: u8 = 0;
        for s in services {
            match s.id.as_str() {
                "MyService" => {
                    assert_eq!(s.protocol_id, "ping");
                    hits |= 0x1;
                    assert!(s.provider.is_none());
                }
                "MyOtherService" => {
                    assert_eq!(s.protocol_id, "pong");
                    hits |= 0x2;
                    assert!(s.provider.is_some());
                    let provider = s.provider.unwrap();
                    assert_eq!(provider.len(), 1);
                    assert!(provider.contains(&("foo".to_string(), "bar".to_string())));
                }
                _ => panic!("unexpected service id"),
            }
        }
        assert_eq!(hits, 0x3); // or did not hit both services.
    }

    #[test]
    fn test_parse_services_with_ports() {
        let tstr = r#"
        [services.MyService]
        protocol = "zpr-oauthrsa"
        port = "3000"
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let mut protocols = HashMap::new();
        cparser.add_default_protocols(&mut protocols);
        let services = cparser.parse_services(&ctx, &protocols);
        if services.is_err() {
            panic!("parse_services failed: {:?}", services);
        }
        assert!(services.is_ok());
        let services = services.unwrap();
        assert_eq!(services.len(), 1);
        let parsed = services.get(0).unwrap();
        assert_eq!(parsed.id, "MyService");
        assert!(parsed.protocol_refinement.is_some());
        let pr = parsed.protocol_refinement.as_ref().unwrap();
        assert_eq!(pr.port, Some("3000".to_string()));
    }

    #[test]
    fn test_parse_bootstrap() {
        let tstr = r#"
        [bootstrap]
        "some.cn.here" = "keyfile.pem"
        "another.cn.here" = "other.keyfile.pem"
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let vs = cparser.parse_bootstrap(&ctx);
        assert!(vs.is_ok());
        let bs = vs.unwrap();

        assert_eq!(bs.bootstraps.len(), 2);
        assert_eq!(
            bs.bootstraps.get("some.cn.here").unwrap(),
            &PathBuf::from("keyfile.pem")
        );
        assert_eq!(
            bs.bootstraps.get("another.cn.here").unwrap(),
            &PathBuf::from("other.keyfile.pem")
        );
    }
}
