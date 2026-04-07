//! Loads and parses a ZPL TOML configuration file into a `Config` struct.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;

use nix::NixPath;
use ring::digest::Digest;
use toml::Table;

use crate::context::CompilationCtx;
use crate::crypto::sha256;
use crate::errors::CompilationError;
use crate::protocols::{IcmpFlowType, PortSpec, Protocol, ProtocolError, ZPR_L7_BUILTINS};
use crate::zpl;
use zpr::policy_types::Attribute;

mod node_link;
mod protocol;
mod service;
mod trusted_service;

use node_link::{parse_link, parse_node, parse_substrate_addrs};
use protocol::parse_protocol;
use service::parse_service;
use trusted_service::parse_trusted_service;

/// Helper to create a ConfigError. Works with a single string (or &str) argument
/// (really anything that has a to_string function), or with two args: a format string and arguments.
///
// TODO: Figure out how to put this in errors.rs
#[macro_export]
macro_rules! err_config {
    ($s:expr_2021) => {
        CompilationError::ConfigError($s.to_string())
    };
    ($s:expr_2021, $($arg:tt)*) => {
        CompilationError::ConfigError(format!($s, $($arg)*))
    };
}

/// Configuration structure which is parsed from the TOML.
#[allow(dead_code)]
pub struct Config {
    pub digest: Digest,
    resolver: Resolver,
    pub nodes: HashMap<String, Node>,
    pub links: HashMap<String, Link>,
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
pub enum ProtocolRefinement {
    Port(Vec<PortSpec>), // override protocol portspec
    Icmp(IcmpFlowType),  // override protocol icmp (needed??)
}

impl ProtocolRefinement {
    pub fn apply(&self, protocol: &mut Protocol) -> Result<(), ProtocolError> {
        match self {
            ProtocolRefinement::Port(ports) => protocol.set_portspec(ports.clone()),
            ProtocolRefinement::Icmp(icmp) => protocol.set_icmp(icmp.clone()),
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
#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub provider: Vec<(String, String)>,
    pub zpr_address: String,
    pub substrate_addrs: Option<HashMap<String, Interface>>,
}

#[derive(Debug, Clone)]
pub struct Link {
    // ID's map to node ID's.
    pub peer_a_id: String,

    // Interfaces map to Node substrate interface IDs.
    pub peer_a_interface: String,

    pub peer_b_id: String,
    pub peer_b_interface: String,

    // Link always gets 'zpr.cost' attribute at least.
    pub attributes: Vec<(String, String)>,
}

/// Interface is part of a node.
#[derive(Debug, Clone)]
pub struct Interface {
    pub host: String, // host or IP
    pub port: u16,
}

/// Visa Service table ("visa_service")
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct VisaService {
    pub dock_node_id: Option<String>,
}

pub struct Bootstrap {
    pub bootstraps: HashMap<String, PathBuf>, // CN -> public-key-pem-file
}

/// Trusted Service table ("trusted_services")
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TrustedService {
    pub id: String,
    pub api: String,
    pub service: Option<String>, // Name of service for VS operations
    pub client: Option<String>,  // Name of service for client operations
    pub cert_path: Option<PathBuf>,
    pub returns_attrs: HashMap<String, Attribute>,
    pub identity_attrs: Vec<String>,
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
    parser.warn_unknown_section(ctx)?;
    parser.parse(ctx)
}

impl ConfigParse {
    fn new_from_toml_str(cstr: &str) -> Result<ConfigParse, CompilationError> {
        let digest = sha256(cstr);

        let ctoml = cstr.parse::<Table>().map_err(CompilationError::TomlError)?;

        Ok(ConfigParse { digest, ctoml })
    }

    fn parse(&mut self, ctx: &CompilationCtx) -> Result<Config, CompilationError> {
        let resolver = self.parse_resolver(ctx)?;
        let nodes = self.parse_nodes(ctx)?;

        // Links if present tie node interfaces together.
        let links = self.parse_links(ctx, &nodes)?;

        let visa_service = match self.parse_visa_service(ctx)? {
            Some(vs) => vs,
            None => VisaService::default(),
        };

        let bootstrap = self.parse_bootstrap(ctx)?;
        let trusted_services = self.parse_trusted_services(ctx)?;
        let mut protocols = self.parse_protocols(ctx)?;
        self.add_default_protocols(&mut protocols);
        let services = self.parse_services(ctx, &protocols)?;
        Ok(Config {
            digest: self.digest,
            resolver,
            nodes,
            links,
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
                Protocol::new_zpr_l7(pname.to_string(), pname.to_string(), None).unwrap(),
            );
        }
    }

    /// Parse the resolver section which is optional.  The defualt is just
    /// to have an `resolver.order` set to [hosts, dns].  The hosts section is optional, but
    /// if present is mapping of hostnames to IP addresses.
    fn parse_resolver(&self, ctx: &CompilationCtx) -> Result<Resolver, CompilationError> {
        if !self.ctoml.contains_key("resolver") {
            return Ok(Resolver::default());
        }
        let r = self.ctoml["resolver"]
            .as_table()
            .ok_or(err_config!("error reading resolver section"))?;
        for elem in r.keys() {
            match elem.as_str() {
                "order" => (),
                "hosts" => (),
                _ => ctx.warn(&format!(
                    "unknown section '{elem}' detected while parsing resolver",
                ))?,
            }
        }

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
    fn parse_nodes(&self, ctx: &CompilationCtx) -> Result<HashMap<String, Node>, CompilationError> {
        if !self.ctoml.contains_key("nodes") {
            return Err(err_config!("missing section: nodes"));
        }
        let nodes = self.ctoml["nodes"]
            .as_table()
            .ok_or(err_config!("error reading nodes section"))?;
        // Within "nodes" each KEY is a node ID that is a table.
        let mut node_map = HashMap::new();
        for (node_id, v) in nodes {
            for reserved in zpl::RESERVED_NODE_IDS {
                if node_id == reserved {
                    return Err(err_config!("node ID '{}' is reserved", node_id));
                }
            }
            let mut n = parse_node(
                node_id,
                v.as_table()
                    .ok_or(err_config!("node {} is not a table", node_id))?,
                ctx,
            )?;

            if let Some(addr_val) = v.get("substrate_addrs") {
                if let Some(tbl) = addr_val.as_table() {
                    let substrate_addrs = parse_substrate_addrs(node_id, tbl, ctx)?;
                    if !substrate_addrs.is_empty() {
                        n.substrate_addrs = Some(substrate_addrs);
                    } else {
                        ctx.warn(
                            format!("node {} has empty substrate_addrs section", node_id).as_str(),
                        )?;
                    }
                }
            }

            node_map.insert(node_id.to_string(), n);
        }
        Ok(node_map)
    }

    /// Parse the links data from the toml configuration.
    ///
    /// Links look like this:
    /// ```toml
    /// [links.link1]
    /// attributes = [["zpr.cost", "10"]]
    /// peers = [{ node = "node1", interface = "if1" }, { node = "node2", interface = "if2" }]
    /// ```
    fn parse_links(
        &self,
        ctx: &CompilationCtx,
        nodes: &HashMap<String, Node>,
    ) -> Result<HashMap<String, Link>, CompilationError> {
        if !self.ctoml.contains_key("links") {
            return Ok(HashMap::new());
        }
        let links = self.ctoml["links"]
            .as_table()
            .ok_or(err_config!("error reading links section"))?;
        let mut link_map = HashMap::new();
        for (link_id, v) in links {
            let mut link = parse_link(
                link_id,
                v.as_table()
                    .ok_or(err_config!("link {} is not a table", link_id))?,
                ctx,
                nodes,
            )?;

            // If link does not have a cost attribute we add it.
            if !link
                .attributes
                .iter()
                .any(|(k, _)| k == zpl::KATTR_LINK_COST)
            {
                link.attributes
                    .push((zpl::KATTR_LINK_COST.to_string(), "1".to_string()));
            }

            link_map.insert(link_id.to_string(), link);
        }
        Ok(link_map)
    }

    /// Parse the very basic visa_service section.
    ///
    /// The only thing in here is dock_node with the node ID.
    /// As we currently only support one node user can just skip
    /// this and we will fill it in automatically.
    ///
    /// TODO: See https://github.com/org-zpr/zpr-compiler/issues/100
    fn parse_visa_service(
        &mut self,
        ctx: &CompilationCtx,
    ) -> Result<Option<VisaService>, CompilationError> {
        if !self.ctoml.contains_key("visa_service") {
            return Ok(None);
        }
        let vs = self.ctoml["visa_service"]
            .as_table()
            .ok_or(err_config!("error reading visa_service section"))?;
        for elem in vs.keys() {
            match elem.as_str() {
                "dock_node" => (),
                _ => ctx.warn(&format!(
                    "unknown section '{elem}' detected while parsing visa_service",
                ))?,
            }
        }
        if !vs.contains_key("dock_node") {
            return Err(err_config!("visa_service missing dock_node"));
        }
        let dock_node_id = vs["dock_node"]
            .as_str()
            .ok_or(err_config!("visa_service missing dock_node"))?
            .to_string();

        Ok(Some(VisaService {
            dock_node_id: Some(dock_node_id),
        }))
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
        let mut default_creates = 0;
        for (ts_id, v) in ts {
            let ts = parse_trusted_service(
                ts_id,
                v.as_table()
                    .ok_or(err_config!("trusted_service {} is not a table", ts_id))?,
                ctx,
            )?;
            if ts.id == zpl::DEFAULT_TRUSTED_SERVICE_ID {
                default_creates += 1;
                if default_creates > 1 {
                    return Err(err_config!("only one default trusted_service allowed"));
                }
            }
            trusted_services.push(ts);
        }
        if default_creates == 0 {
            let returns = HashMap::from([(
                zpl::KATTR_CN.to_string(),
                Attribute::tuple(zpl::KATTR_CN).single().build().unwrap(),
            )]);
            let ts = TrustedService {
                id: zpl::DEFAULT_TRUSTED_SERVICE_ID.to_string(),
                api: zpl::DEFAULT_TRUSTED_SERVICE_API.to_string(),
                cert_path: None,
                returns_attrs: returns,
                identity_attrs: vec![zpl::KATTR_CN.to_string()],
                provider: None,
                client: None,
                service: None,
            };
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
                ctx,
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
                ctx,
            )?;
            ret.push(s);
        }
        Ok(ret)
    }

    fn warn_unknown_section(&self, ctx: &CompilationCtx) -> Result<(), CompilationError> {
        for elem in self.ctoml.keys() {
            match elem.as_str() {
                "resolver" => (),
                "nodes" => (),
                "links" => (),
                "visa_service" => (),
                "bootstrap" => (),
                "trusted_services" => (),
                "protocols" => (),
                "services" => (),
                _ => ctx.warn(&format!(
                    "unknown section '{elem}' detected while parsing config",
                ))?,
            }
        }

        Ok(())
    }
}

/// Parse attribute tuples from a TOML table field.
///
/// This is how we generally encode ZPR attriutes into the toml, for example:
///
/// ```toml
/// attributes = [["some.key","some value"], ["other.key", "other value"]]
/// ```
///
/// `ctx` is a helpful string to help user understand where in the config we are.
///
/// Pass the field name (in above example that would be `attributes`)
/// and this will return a vector of (key, value) tuples.
///
/// If key is not found, returns None.
pub(super) fn parse_attribute_tuples(
    ctx: &str,
    table: &Table,
    field_name: &str,
) -> Result<Option<Vec<(String, String)>>, CompilationError> {
    if !table.contains_key(field_name) {
        return Ok(None);
    }
    let attr_tuples = table[field_name]
        .as_array()
        .ok_or(err_config!("{} {field_name} is not an array", ctx))?;

    let attrs = tuples_to_tuple_str_vec(ctx, attr_tuples)?;
    Ok(Some(attrs))
}

pub(super) fn parse_provider(
    ctx: &str,
    table: &Table,
) -> Result<Vec<(String, String)>, CompilationError> {
    match parse_attribute_tuples(ctx, table, "provider")? {
        Some(attrs) => Ok(attrs),
        None => Err(err_config!("{} missing provider", ctx)),
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocols::IanaProtocol;

    #[test]
    fn test_parse_resolver_empty() {
        let tstr = r#"
        [resolver]
        "#;
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let r = cparser.parse_resolver(&CompilationCtx::new(false, false));
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
        let r = cparser.parse_resolver(&CompilationCtx::new(false, false));
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
    fn test_parse_attribute_tuples() {
        let tstr = r#"
        [foo]
        provider = [["k1", "v1"], ["k2", 99]]

        [fee]
        # should return empty vector.
        attrs = []

        [fox]
        nope = "no attrs here"
        "#;
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        {
            let foo_tbl = cparser.ctoml["foo"].as_table().unwrap();
            let attrs = parse_attribute_tuples("foo", foo_tbl, "provider");
            assert!(attrs.is_ok(), "{:?}", attrs);
            let attrs = attrs.unwrap();
            assert!(attrs.is_some());
            let attrs = attrs.unwrap();
            assert_eq!(attrs.len(), 2);
            assert!(attrs.contains(&("k1".to_string(), "v1".to_string())));
        }
        {
            let fee_tbl = cparser.ctoml["fee"].as_table().unwrap();
            let attrs = parse_attribute_tuples("fee", fee_tbl, "attrs");
            assert!(attrs.is_ok(), "{:?}", attrs);
            let attrs = attrs.unwrap();
            assert!(attrs.is_some());
        }
        {
            let fox_tbl = cparser.ctoml["fox"].as_table().unwrap();
            let attrs = parse_attribute_tuples("fox", fox_tbl, "missing");
            assert!(attrs.is_ok(), "{:?}", attrs);
            let attrs = attrs.unwrap();
            assert!(attrs.is_none());
        }
    }

    #[test]
    fn test_parse_node() {
        let tstr = r#"
        [nodes]
        [nodes.n0]
        zpr_address = "foo.zpr"
        provider = [["zpr.foo", "bar"], ["baz", 99]]
        [nodes.n0.substrate_addrs]
        "eth0" = "1.2.3.4:2000"
        "eth1" = "foo.addr:9000"
        "#;
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let nodes = cparser.parse_nodes(&CompilationCtx::new(false, false));
        assert!(nodes.is_ok(), "{:?}", nodes);
        let nodes = nodes.unwrap();
        assert_eq!(nodes.len(), 1);
        let n0 = nodes.get("n0").unwrap();
        assert_eq!(n0.id, "n0");
        assert_eq!(n0.zpr_address, "foo.zpr");
        let sub_addrs = n0.substrate_addrs.as_ref().unwrap();
        assert_eq!(sub_addrs.len(), 2);
        for (ifname, iface) in sub_addrs {
            match ifname.as_str() {
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
        assert!(
            n0.provider
                .contains(&("zpr.foo".to_string(), "bar".to_string()))
        );
        assert!(n0.provider.contains(&("baz".to_string(), "99".to_string())));
    }

    #[test]
    fn test_parse_links() {
        let tstr = r#"
        [nodes]

        [nodes.n0]
        zpr_address = "foo.zpr"
        provider = [["zpr.foo", "bar"], ["baz", 99]]
        [nodes.n0.substrate_addrs]
        "i0" = "1.2.3.4:2000"

        [nodes.n1]
        zpr_address = "fee.zpr"
        provider = [["zpr.foo", "barf"], ["buz", 100]]
        [nodes.n1.substrate_addrs]
        "j0" = "4.5.6.7:2000"

        [links.n0n1]
        peers = [{ node = "n0" }, { node = "n1" }]
        "#;

        let ctx = CompilationCtx::new(false, false);
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let nodes = cparser.parse_nodes(&ctx);
        assert!(nodes.is_ok(), "{:?}", nodes);
        let nodes = nodes.unwrap();
        assert_eq!(nodes.len(), 2);
        let n0 = nodes.get("n0").unwrap();
        assert_eq!(n0.id, "n0");
        let n1 = nodes.get("n1").unwrap();
        assert_eq!(n1.id, "n1");

        let links = cparser.parse_links(&ctx, &nodes);
        assert!(links.is_ok(), "{:?}", links);

        let links = links.unwrap();
        assert_eq!(links.len(), 1);
        let l0 = links.get("n0n1").unwrap();
        assert_eq!(l0.peer_a_id, "n0");
        assert_eq!(l0.peer_b_id, "n1");

        assert_eq!(l0.peer_a_interface, "i0".to_string());
        assert_eq!(l0.peer_b_interface, "j0".to_string());

        assert_eq!(l0.attributes.len(), 1);
        assert_eq!(l0.attributes[0].0, zpl::KATTR_LINK_COST);
    }

    #[test]
    fn test_parse_links_multi_iface_missing_iface_spec() {
        let tstr = r#"
        [nodes]

        [nodes.n0]
        zpr_address = "foo.zpr"
        provider = [["zpr.foo", "bar"], ["baz", 99]]
        [nodes.n0.substrate_addrs]
        "i0" = "1.2.3.4:2000"
        "i1" = "1.2.3.5:2000"
        "i2" = "1.2.3.6:2000"

        [nodes.n1]
        zpr_address = "fee.zpr"
        provider = [["zpr.foo", "barf"], ["buz", 100]]
        [nodes.n1.substrate_addrs]
        "j0" = "4.5.6.7:2000"
        "j1" = "4.5.6.8:2000"

        [links.n0n1]
        # will fail since missing intercace names
        peers = [{ node = "n0" }, { node = "n1" }]
        "#;

        let ctx = CompilationCtx::new(false, false);
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let nodes = cparser.parse_nodes(&ctx);
        assert!(nodes.is_ok(), "{:?}", nodes);
        let nodes = nodes.unwrap();
        assert_eq!(nodes.len(), 2);
        let n0 = nodes.get("n0").unwrap();
        assert_eq!(n0.id, "n0");
        let n1 = nodes.get("n1").unwrap();
        assert_eq!(n1.id, "n1");

        let links = cparser.parse_links(&ctx, &nodes);
        assert!(
            links.is_err(),
            "expected error due to missing interface spec, got: {:?}",
            links
        );
    }

    #[test]
    fn test_parse_links_multi_iface_requires_iface_spec() {
        let tstr = r#"
        [nodes]

        [nodes.n0]
        zpr_address = "foo.zpr"
        provider = [["zpr.foo", "bar"], ["baz", 99]]
        [nodes.n0.substrate_addrs]
        "i0" = "1.2.3.4:2000"
        "i1" = "1.2.3.5:2000"
        "i2" = "1.2.3.6:2000"

        [nodes.n1]
        zpr_address = "fee.zpr"
        provider = [["zpr.foo", "barf"], ["buz", 100]]
        [nodes.n1.substrate_addrs]
        "j0" = "4.5.6.7:2000"
        "j1" = "4.5.6.8:2000"

        [links.n0n1]
        # Also override cost
        attributes = [["zpr.cost", "5"]]
        peers = [{ node = "n0", interface = "i2"}, { node = "n1", interface = "j1" }]
        "#;

        let ctx = CompilationCtx::new(false, false);
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let nodes = cparser.parse_nodes(&ctx);
        assert!(nodes.is_ok(), "{:?}", nodes);
        let nodes = nodes.unwrap();
        assert_eq!(nodes.len(), 2);
        let n0 = nodes.get("n0").unwrap();
        assert_eq!(n0.id, "n0");
        let n1 = nodes.get("n1").unwrap();
        assert_eq!(n1.id, "n1");

        let links = cparser.parse_links(&ctx, &nodes);
        assert!(links.is_ok(), "{:?}", links);

        let links = links.unwrap();
        assert_eq!(links.len(), 1);
        let l0 = links.get("n0n1").unwrap();
        assert_eq!(l0.peer_a_id, "n0");
        assert_eq!(l0.peer_b_id, "n1");

        assert_eq!(l0.peer_a_interface, "i2".to_string());
        assert_eq!(l0.peer_b_interface, "j1".to_string());

        assert_eq!(l0.attributes.len(), 1);
        assert_eq!(l0.attributes[0].0, zpl::KATTR_LINK_COST);
        assert_eq!(l0.attributes[0].1, "5");
    }

    #[test]
    fn test_parse_links_multiple() {
        let tstr = r#"
        [nodes]

        [nodes.n0]
        zpr_address = "foo.zpr"
        provider = [["zpr.foo", "bar"], ["baz", 99]]

        [nodes.n0.substrate_addrs]
        "i0" = "1.2.3.4:2000"

        [nodes.n1]
        zpr_address = "fee.zpr"
        provider = [["zpr.foo", "barf"], ["buz", 100]]

        [nodes.n1.substrate_addrs]
        "j0" = "4.5.6.7:2000"
        "j1" = "4.5.6.8:2000"

        [nodes.n2]
        zpr_address = "fee.zpr"
        provider = [["zpr.foo", "barf"], ["buz", 100]]

        [nodes.n2.substrate_addrs]
        "k0" = "4.5.6.7:2000"
        "k1" = "4.5.6.8:2000"


        [links.n0n1]
        peers = [{ node = "n0"}, { node = "n1", interface = "j0" }]

        [links.n1n2]
        peers = [{ node = "n1", interface = "j1"}, { node = "n2", interface = "k0" }]

        [links.n0n2]
        peers = [{ node = "n0"}, { node = "n2", interface = "k1" }]
        "#;

        let ctx = CompilationCtx::new(false, false);
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let nodes = cparser.parse_nodes(&ctx);
        assert!(nodes.is_ok(), "{:?}", nodes);
        let nodes = nodes.unwrap();
        assert_eq!(nodes.len(), 3);

        let links = cparser.parse_links(&ctx, &nodes);
        assert!(links.is_ok(), "{:?}", links);

        let links = links.unwrap();
        assert_eq!(links.len(), 3);
        let l0 = links.get("n0n1").unwrap();
        assert_eq!(l0.peer_a_id, "n0");
        assert_eq!(l0.peer_b_id, "n1");
        let l1 = links.get("n1n2").unwrap();
        assert_eq!(l1.peer_a_id, "n1");
        assert_eq!(l1.peer_b_id, "n2");
        let l2 = links.get("n0n2").unwrap();
        assert_eq!(l2.peer_a_id, "n0");
        assert_eq!(l2.peer_b_id, "n2");
    }

    #[test]
    fn test_parse_node_reserved_id() {
        let tstr = r#"
        [nodes]
        [nodes.visaservice]
        key = "somekey"
        zpr_address = "foo.zpr"
        provider = [["zpr.foo", "bar"], ["baz", 99]]
        interfaces = ["eth0", "eth1"]
        eth0.netaddr = "1.2.3.4:2000"
        eth1.netaddr = "foo.addr:9000"
        "#;
        let cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let nodes = cparser.parse_nodes(&CompilationCtx::new(false, false));
        assert!(nodes.is_err());
        let err = nodes.unwrap_err();
        assert!(err.to_string().contains("is reserved"));
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
        assert_eq!(vs.unwrap().dock_node_id, Some("n0".to_string()));
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
        assert_eq!(
            ts.returns_attrs[zpl::KATTR_CN].zpl_key(),
            "endpoint.zpr.adapter.cn"
        );
        assert_eq!(ts.identity_attrs.len(), 1);
        assert_eq!(ts.identity_attrs[0], "endpoint.zpr.adapter.cn");
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
        returns_attributes = ["a -> user.a", "c -> user.c"]
        identity_attributes = ["c"]
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
        assert_eq!(services.len(), 2);
        let ts = services.get(0).unwrap();
        assert_eq!(ts.id, "other");
        assert_eq!(ts.api, "validation/2");
        assert_eq!(ts.cert_path, Some(PathBuf::from("foo.pem")));
        assert_eq!(ts.returns_attrs.len(), 2);
        assert_eq!(ts.returns_attrs["a"].zpl_key(), "user.a");
        assert_eq!(ts.returns_attrs["c"].zpl_key(), "user.c");
        assert_eq!(ts.identity_attrs.len(), 1);
        assert!(ts.identity_attrs[0] == "c");
    }

    #[test]
    fn test_parse_trusted_service_unique_keys() {
        // Should fail because we have duplicate keys (even though different namespaces)
        let tstr = r##"
        [trusted_services.other]
        api = "validation/2"
        cert_path = "foo.pem"
        prefix = "bar.hop"
        returns_attributes = ["foo -> user.foo", "fee -> user.fee", "foo -> #endpoint.foo"]
        identity_attributes = ["foo"]
        provider = [["foo", "bar"]]
        "##;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let services = cparser.parse_trusted_services(&ctx);
        assert!(services.is_err());
        // check that error message contains the duplicate key
        if let Err(e) = services {
            assert!(
                e.to_string().contains("duplicate"),
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
        returns_attributes = ["a -> user.a", "c -> user.c"]
        identity_attributes = ["c"]
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
        assert_eq!(services.len(), 2);
        let ts = services.get(0).unwrap();
        assert_eq!(ts.id, "other");
        assert_eq!(ts.api, "validation/2");
        assert_eq!(ts.cert_path, Some(PathBuf::from("foo.pem")));
        assert_eq!(ts.returns_attrs.len(), 2);
        assert_eq!(ts.identity_attrs.len(), 1);
        assert_eq!(ts.client, Some("other-client".to_string()));
        assert_eq!(ts.service, Some("other-vs".to_string()));
    }

    #[test]
    fn test_parse_trusted_service_bas() {
        let tstr = r#"
        [trusted_services.bas]
        api = "validation/2"
        cert_path = "foo.crt"
        returns_attributes = ["a -> user.a", "c -> user.c"]
        identity_attributes = ["c"]
        provider = [["foo", "bar"]]
        client = "bas-client-interface"
        service = "bas-vs-interface"
        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let services = cparser.parse_trusted_services(&ctx);
        assert!(services.is_ok(), "{:?}", services.unwrap_err());
        let services = services.unwrap();
        assert_eq!(services.len(), 2);
        let ts = services.get(0).unwrap();
        assert_eq!(ts.id, "bas");
        assert_eq!(ts.api, "validation/2");
        assert_eq!(ts.cert_path, Some(PathBuf::from("foo.crt")));
        assert!(ts.provider.is_some());
        let provider = ts.provider.as_ref().unwrap();
        assert_eq!(provider.len(), 1);
        assert!(provider.contains(&("foo".to_string(), "bar".to_string())));
        assert_eq!(ts.returns_attrs.len(), 2);
        assert_eq!(ts.identity_attrs.len(), 1);
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
        assert_eq!(http.get_port().unwrap(), &vec![PortSpec::Single(80)]);
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
    fn test_parse_protocols_with_port_specs() {
        let tstr = r#"
        [protocols.http]
        l4protocol = "iana.Tcp"
        port = "80, 443, 8080-8081, 31337"

        "#;
        let mut cparser = ConfigParse::new_from_toml_str(tstr).unwrap();
        let ctx = CompilationCtx::default();
        let prots = cparser.parse_protocols(&ctx);
        assert!(prots.is_ok());
        let prots = prots.unwrap();
        assert_eq!(prots.len(), 1);
        let http = prots.get("http").unwrap();
        assert_eq!(http.get_layer4(), IanaProtocol::TCP);
        assert_eq!(
            http.get_port().unwrap(),
            &vec![
                PortSpec::Single(80),
                PortSpec::Single(443),
                PortSpec::Range(8080, 8081),
                PortSpec::Single(31337),
            ]
        );
        assert!(!http.is_icmp());
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
            "ping".to_string(),
            Protocol::icmp6("ping", IcmpFlowType::OneShot(vec![128, 129]))
                .build()
                .unwrap(),
        );
        protocols.insert(
            String::from("pong"),
            Protocol::icmp6("pong", IcmpFlowType::OneShot(vec![128, 129]))
                .build()
                .unwrap(),
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
        assert!(matches!(pr, ProtocolRefinement::Port(_)));
        let ports = match pr {
            ProtocolRefinement::Port(p) => p,
            _ => panic!("unexpected protocol refinement"),
        };
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], PortSpec::Single(3000));
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
