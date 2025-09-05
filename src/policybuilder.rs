//! policybuilder.rs - Build a protocol buffer policy from the fabric.

use ::polio;
use chrono::prelude::*;
use std::collections::HashMap;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::context::CompilationCtx;
use crate::errors::CompilationError;
use crate::fabric::{Fabric, FabricService, ServiceType};
use crate::protocols::IcmpFlowType;
use crate::ptypes::Attribute;
use crate::zpl;

/// This value for a PROC in a connect record means NO PROC.
pub const NO_PROC: u32 = u32::MAX; // 0xffffffff

#[allow(dead_code)]
#[derive(Default)]
pub struct PolicyBuilder {
    verbose: bool,
    policy_date: String,
    policy: polio::Policy,
    connects_table: HashMap<String, usize>, // connect hash string -> connect index

    // Before writing service IDs into the policy we clean up the names by converting
    // whitespace into underscores.  This map keeps track of that so that we use the
    // same "mangled" names for fabric service names throughout the policy.
    name_mangler: HashMap<String, String>, // fabric IDs -> policy IDs
}

/// These flags are used to set the type of service in the PROC.
/// TODO: Maybe switch to using the protocol buffer type directly?
#[derive(Debug, Clone, PartialEq, Copy)]
struct PFlags {
    pub node: bool,
    pub vs: bool,
    pub vs_dock: bool,
}

impl PFlags {
    /// Create the set of flags for a node.
    pub fn node() -> PFlags {
        PFlags {
            node: true,
            vs: false,
            vs_dock: true,
        }
    }

    /// Create the set of flags for a visa service.
    pub fn vs() -> PFlags {
        PFlags {
            node: false,
            vs: true,
            vs_dock: false,
        }
    }
}

/// That which can create a policy, requires a [Fabric] to do so.
impl PolicyBuilder {
    /// Create the builder. This sets some topical info in the policy.
    ///
    /// Once created, you should call [PolicyBuilder::with_max_visa_lifetime], then
    /// [PolicyBuilder::with_fabric] (which does the real work), and finally
    /// [PolicyBuilder::build] to get the compiled policy.
    pub fn new(verbose: bool) -> PolicyBuilder {
        let utc: DateTime<Utc> = Utc::now();
        let policy_date = utc.to_rfc3339_opts(SecondsFormat::Secs, true);
        let tsnow = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let policy_version = tsnow.as_secs();

        let pp = polio::Policy {
            policy_date: policy_date.clone(),
            policy_version: policy_version,
            policy_metadata: metadata(&policy_date),
            ..Default::default()
        };

        if verbose {
            println!("creating binary policy");
            println!("metadata: {}", pp.policy_metadata);
        }

        PolicyBuilder {
            verbose,
            policy_date,
            policy: pp,
            connects_table: HashMap::new(),
            name_mangler: HashMap::new(),
        }
    }

    /// Returns the built policy. This doesn't actually do anything except return the already built policy.
    /// you must call [PolicyBuilder::with_fabric] to do the real work before calling this.
    pub fn build(self) -> Result<polio::Policy, CompilationError> {
        Ok(self.policy)
    }

    /// The binary policy has a place for global settings, the only valid
    /// one in the prototype is "max visa lifetime".  Set that here.
    pub fn with_max_visa_lifetime(&mut self, lifetime: Duration) {
        let cs = polio::ConfigSetting {
            key: zpl::CONFIG_KEY_MAX_VISA_LIFETIME,
            val: Some(polio::config_setting::Val::U64v(lifetime.as_secs())),
        };
        self.policy.config.push(cs);
    }

    /// From the Fabric we get a bunch of details for the policy.
    ///
    ///   - The set of connects, which describe what agents can connect to the network.
    ///   - The "procs" which are little programs that run when an agent connects.
    ///   - The attribute keys and values lookup tables.
    ///   - The set of communication policies which set which agents can access which services.
    ///   - The links which are empty for now as only a single node is supported (TODO).
    ///   - The services which is only used for AUTH services.
    ///   - The certificates used for trusted services and for the default/internal auth service.
    ///
    /// This does most of the work in building the policy.
    pub fn with_fabric(
        &mut self,
        fabric: &Fabric,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        self.policy.policy_revision = fabric.revision.clone();

        // The policy refers to attribute keys and values using a lookup table.
        let mut key_table = HashMap::new(); // key -> index
        let mut value_table = HashMap::new(); // value -> index

        self.populate_key_table(fabric, &mut key_table);
        self.populate_value_table(fabric, &mut value_table);
        self.policy.attr_key_index = self.index_from_table(&key_table);
        self.policy.attr_val_index = self.index_from_table(&value_table);

        self.set_connects(fabric)?;
        self.set_policies(fabric)?;
        self.set_default_auth(fabric, ctx)?;
        self.set_bootstrap(fabric, ctx)?;
        self.set_auth_services(fabric, ctx)?;

        if self.verbose {
            println!("  {} connect rules", self.policy.connects.len());
            println!("  {} trusted services", self.policy.services.len());
            println!("  {} communication policies", self.policy.policies.len());
            println!(
                "  {} attr keys / {} attr values",
                self.policy.attr_key_index.len() - 1,
                self.policy.attr_val_index.len() - 1
            );
        }
        Ok(())
    }

    /// Configure the default (internal) authentication service in the policy. This is
    /// essentially just storing a CA certificate along with the expected prefix.
    fn set_default_auth(
        &mut self,
        fabric: &Fabric,
        _ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        if fabric.default_auth_cert_asn.is_empty() {
            return Ok(());
        }
        let pcert = polio::Cert {
            id: (self.policy.certificates.len() + 1) as u32,
            asn1data: fabric.default_auth_cert_asn.clone(),
            name: zpl::DEFAULT_TS_PREFIX.to_string(),
        };
        self.policy.certificates.push(pcert);
        Ok(())
    }

    fn set_auth_services(
        &mut self,
        fabric: &Fabric,
        _ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        for svc in &fabric.services {
            let apiname: String = match svc.service_type {
                ServiceType::Trusted(ref t) => t.clone(),
                _ => {
                    continue; // not a trusted service
                }
            };

            if apiname != zpl::TS_API_V2 {
                return Err(CompilationError::ConfigError(format!(
                    "trusted service {}: only 'validation/2' api supported, not '{}'",
                    svc.config_id, apiname
                )));
            }

            if svc.client_service_name.is_none() {
                return Err(CompilationError::ConfigError(format!(
                    "trusted service {}: missing client facing service name",
                    svc.config_id
                )));
            }

            // The trusted service actually has two addresses.
            // The vs-address which is service named <id>-vs
            // And the adapter auth address whic is at <id>-<client-service-name>

            // The VS facing service details have been copied out of config.

            let canonical_svc_id = self.get_canonical_service_name(&svc.config_id);

            // pretty sure it is an error if config_id != fabric_id in these cases.
            // TODO: Not sure why we are using config_id here and not fabric_id.
            if svc.config_id != svc.fabric_id {
                panic!(
                    "logic error - config_id '{}' is not same as fabric id '{}'",
                    svc.config_id, svc.fabric_id
                );
            }

            if let Some((l7p, port)) = svc.get_l7protocol_and_port() {
                let trusted_svc = polio::Service {
                    r#type: polio::SvcT::SvctAuth.into(),
                    name: canonical_svc_id.clone(),
                    prefix: canonical_svc_id,
                    domain: String::new(),
                    query_uri: String::new(), // n/a
                    validate_uri: format!("{}://[::1]:{}", l7p, port),
                    attrs: svc.returns_attrs.clone().unwrap_or_default(),
                    id_attrs: svc.identity_attrs.clone().unwrap_or_default(),
                };
                self.policy.services.push(trusted_svc);
            } else {
                return Err(CompilationError::ConfigError(format!(
                    "trusted service {}: must have single port number",
                    svc.config_id
                )));
            }

            // The adapter facing auth service (if present) we register as a new-style "authentication" service.
            if let Some(asvc) = fabric.get_service(svc.client_service_name.as_ref().unwrap()) {
                // TODO: Not sure why we are using config_id here and not fabric_id.
                if asvc.config_id != asvc.fabric_id {
                    panic!(
                        "logic error - config_id '{}' is not same as fabric id '{}'",
                        asvc.config_id, asvc.fabric_id
                    );
                }
                let canonical_asvc_id = self.get_canonical_service_name(&asvc.config_id);
                if let Some((l7p, port)) = asvc.get_l7protocol_and_port() {
                    let auth_svc = polio::Service {
                        r#type: polio::SvcT::SvctActorAuth.into(),
                        name: canonical_asvc_id.clone(),
                        prefix: canonical_asvc_id,
                        domain: String::new(),
                        query_uri: String::new(), // n/a
                        validate_uri: format!("{}://[::1]:{}", l7p, port),
                        attrs: Vec::new(),    // do not set for adapter facing
                        id_attrs: Vec::new(), // do not set for adapter facing
                    };
                    self.policy.services.push(auth_svc);
                } else {
                    return Err(CompilationError::ConfigError(format!(
                        "authentication service {}: must have single port number",
                        asvc.config_id
                    )));
                }
            } else {
                // Not found. This means that either the service has no adapter facing offering
                // (ie, it is a query only service). Or the user did not add any ZPL allowing
                // access -- which is warned about in a previous parsing step.
            }
        }
        Ok(())
    }

    fn set_bootstrap(
        &mut self,
        fabric: &Fabric,
        _ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        for (cnval, keydata) in &fabric.bootstrap_records {
            self.policy.pubkeys.push(polio::PublicKey {
                cn: cnval.clone(),
                keydata: keydata.clone(),
            });
        }
        Ok(())
    }

    // Each policy (called a CPolicy for "Communication Policy" in the protobuf)
    // lists a service, a scope (which is a protocol/port) and a collection
    // of attributes.  For a policy to be satisfied at the visa service ALL
    // the condititions must be met by the CLIENT.
    //
    // Conditions that must be met by the service are stored in the `svc_conditions`
    // field. Note that some service conditions are applied in a connect policy.
    // Eg, an actor is not permitted to advertise a service unless it has some specific
    // conditions.
    //
    // As an aside, i'm not exactly sure why the protobuf format has a list of
    // lists of conditions rather than just a list.
    fn set_policies(&mut self, fabric: &Fabric) -> Result<(), CompilationError> {
        // Each service has a set of client policies.
        // Each policy is a list of conditions that permit access to the service.
        // We convert each policy to its own CPolicy.

        for svc in &fabric.services {
            let pscope = self.scope_for_service(svc)?;
            let mut pcount = 0;

            for policy in &svc.client_policies {
                pcount += 1;
                let canonical_svc_id = self.get_canonical_service_name(&svc.fabric_id);
                let mut cpol = polio::CPolicy {
                    service_id: canonical_svc_id.clone(),
                    id: canonical_svc_id.clone(), // TODO: Not sure why we have both id and service_id.
                    scope: pscope.clone(),
                    cli_conditions: Vec::new(),
                    svc_conditions: Vec::new(),
                    constraints: Vec::new(), // TODO
                    allow: !policy.never_allow,
                };
                if !policy.cli_condition.is_empty() {
                    let exprs = self.attr_list_to_attrexpr(&policy.cli_condition);
                    let cond = polio::Condition {
                        // TODO: In old ZPL we copied down the docstring from the ZPL into this ID.
                        id: format!("{}-{}c", canonical_svc_id, pcount),
                        attr_exprs: exprs,
                    };
                    cpol.cli_conditions.push(cond);
                }
                if !policy.svc_condition.is_empty() {
                    let exprs = self.attr_list_to_attrexpr(&policy.svc_condition);
                    let cond = polio::Condition {
                        // TODO: In old ZPL we copied down the docstring from the ZPL into this ID.
                        id: format!("{}-{}s", canonical_svc_id, pcount),
                        attr_exprs: exprs,
                    };
                    cpol.svc_conditions.push(cond);
                }
                self.policy.policies.push(cpol);
            }
        }

        Ok(())
    }

    /// Create a polio::Scope from a FabricService.protocol.
    /// Only services with protocols should be passed here.
    fn scope_for_service(
        &self,
        svc: &FabricService,
    ) -> Result<Vec<polio::Scope>, CompilationError> {
        let mut scopes = Vec::new();

        // The visa service and policy protobuf support a much richer protcol description than
        // we do in our current ZPL parser.  The current ZPL supports one protocol and one port
        // per service.

        let parg: polio::scope::Protarg;

        if svc.protocol.is_none() {
            panic!(
                "cannot call scope_for_service on a service with no protocol: {}",
                svc.config_id
            );
        }
        let svc_prot = svc.protocol.clone().unwrap();

        match &svc_prot.get_icmp() {
            Some(icmp) => {
                let picmp = match icmp {
                    IcmpFlowType::OneShot(codes) => {
                        let pcodes = codes.iter().map(|c| *c as u32).collect();
                        polio::Icmp {
                            r#type: polio::Icmpt::Once as i32,
                            codes: pcodes,
                        }
                    }
                    IcmpFlowType::RequestResponse(req, resp) => {
                        let pcodes = vec![*req as u32, *resp as u32];
                        polio::Icmp {
                            r#type: polio::Icmpt::Reqrep as i32,
                            codes: pcodes,
                        }
                    }
                };
                parg = polio::scope::Protarg::Icmp(picmp);
            }
            None => {
                match &svc_prot.get_port() {
                    Some(port_str) => {
                        let port_num: u16 = match port_str.parse() {
                            Ok(n) => n,
                            Err(_) => {
                                return Err(CompilationError::ConfigError(format!(
                                    "service {} port '{}' is invalid or out of range",
                                    svc.config_id, &port_str
                                )));
                            }
                        };
                        let pspec = polio::PortSpecList {
                            spec: vec![polio::PortSpec {
                                parg: Some(polio::port_spec::Parg::Port(port_num as u32)),
                            }],
                        };
                        parg = polio::scope::Protarg::Pspec(pspec);
                    }
                    None => {
                        // TODO: Catch this earlier when we revamp port parsing.
                        return Err(CompilationError::ConfigError(format!(
                            "service {} protcol must be ICMP or have a valid port",
                            svc.config_id
                        )));
                    }
                }
            }
        }

        let scope = polio::Scope {
            protocol: svc_prot.get_layer4().into(),
            protarg: Some(parg),
        };
        scopes.push(scope);

        Ok(scopes)
    }

    fn set_connects(&mut self, fabric: &Fabric) -> Result<(), CompilationError> {
        for svc in &fabric.services {
            // Any agent that can access a service can connect
            for clipol in &svc.client_policies {
                if !clipol.access_only {
                    let pconnect = polio::Connect {
                        attr_exprs: self.attr_list_to_attrexpr(&clipol.cli_condition),
                        proc: NO_PROC,
                    };
                    self.add_connect(pconnect);
                }
            }
            // Any agent that provides a service can connect
            match svc.service_type {
                ServiceType::Regular
                | ServiceType::Visa
                | ServiceType::BuiltIn
                | ServiceType::Authentication => {
                    let flags = if svc.service_type == ServiceType::Visa {
                        Some(PFlags::vs())
                    } else {
                        None
                    };
                    let proc = self.create_service_proc(
                        &svc.fabric_id,
                        &svc.service_type,
                        &svc.protocol.as_ref().unwrap().to_endpoint_str(),
                        flags,
                    );
                    self.policy.procs.push(proc);
                    let proc_idx = self.policy.procs.len() as u32 - 1;
                    let pconnect = polio::Connect {
                        attr_exprs: self.attr_list_to_attrexpr(&svc.provider_attrs),
                        proc: proc_idx,
                    };
                    self.add_connect(pconnect);
                }

                ServiceType::Trusted(_) => {
                    let proc = self.create_service_proc(
                        &svc.fabric_id,
                        &svc.service_type,
                        &svc.protocol.as_ref().unwrap().to_endpoint_str(),
                        None,
                    );
                    self.policy.procs.push(proc);
                    let proc_idx = self.policy.procs.len() as u32 - 1;
                    let pconnect = polio::Connect {
                        attr_exprs: self.attr_list_to_attrexpr(&svc.provider_attrs),
                        proc: proc_idx,
                    };
                    self.add_connect(pconnect);
                    if let Some(cert_data) = &svc.certificate {
                        let pcert = polio::Cert {
                            id: self.policy.certificates.len() as u32 + 1, // note: we do not use ID of 0
                            asn1data: cert_data.clone(),
                            name: svc.fabric_id.clone(),
                        };
                        self.policy.certificates.push(pcert);
                    };
                }
                ServiceType::Undefined => {
                    panic!("undefined service type in fabric{}", svc.config_id);
                }
            }
        }
        // Any agent that provides a node can connect
        for node in &fabric.nodes {
            // The visa service needs the node to register as a service, but the
            // only service on a node is really the visa support service, but we
            // create that as a separate service elsewhere.
            //
            // So this registers as node service but uses a bogus endpoint.
            let proc = self.create_service_proc(
                format!("/zpr/{}", &node.node_id).as_str(),
                &ServiceType::Regular,
                "TCP/1",
                Some(PFlags::node()),
            );
            self.policy.procs.push(proc);
            let proc_idx = self.policy.procs.len() as u32 - 1;
            let pconnect = polio::Connect {
                attr_exprs: self.attr_list_to_attrexpr(&node.provider_attrs),
                proc: proc_idx,
            };
            // Prototype comiler also adss a SetCfg OP to the proc for configuring the CIDR.
            // Presumably this is info for the node to use to hand out addresses, but it is
            // no longer used in prototype.
            //self.policy.connects.push(pconnect);
            self.add_connect(pconnect);
        }
        Ok(())
    }

    /// Create a PROC for the policy binary to register a service and optionally set flags.
    /// `endpoint_str` is comma separated list of endpoint values.
    fn create_service_proc(
        &mut self,
        svc_id: &str,
        svc_type: &ServiceType,
        endpoint_str: &str,
        flags: Option<PFlags>,
    ) -> polio::Proc {
        let mut proc = Vec::new();

        // Args for register are (NAME:String, Type:SvcT, ENDPOINTS:String)
        let mut args = Vec::new();

        let canonical_svc_id = self.get_canonical_service_name(svc_id);

        args.push(polio::Argument {
            arg: Some(polio::argument::Arg::Strval(canonical_svc_id.to_string())),
        });
        let svc_t = match svc_type {
            ServiceType::Regular | ServiceType::Visa | ServiceType::BuiltIn => polio::SvcT::SvctDef,
            ServiceType::Authentication => polio::SvcT::SvctActorAuth,
            ServiceType::Trusted(_) => polio::SvcT::SvctAuth,
            ServiceType::Undefined => panic!("undefined service type"),
        };

        args.push(polio::Argument {
            arg: Some(polio::argument::Arg::Svcval(svc_t as i32)),
        });
        args.push(polio::Argument {
            arg: Some(polio::argument::Arg::Strval(endpoint_str.to_string())),
        });

        let register = polio::Instruction {
            opcode: polio::OpCodeT::OpRegister as i32,
            args,
        };
        proc.push(register);

        if let Some(pf) = flags {
            if pf.node {
                let set_flag = polio::Instruction {
                    opcode: polio::OpCodeT::OpSetFlag as i32,
                    args: vec![polio::Argument {
                        arg: Some(polio::argument::Arg::Flagval(polio::FlagT::FNode as i32)),
                    }],
                };
                proc.push(set_flag);
            }
            if pf.vs {
                let set_flag = polio::Instruction {
                    opcode: polio::OpCodeT::OpSetFlag as i32,
                    args: vec![polio::Argument {
                        arg: Some(polio::argument::Arg::Flagval(
                            polio::FlagT::FVisaservice as i32,
                        )),
                    }],
                };
                proc.push(set_flag);
            }
            if pf.vs_dock {
                let set_flag = polio::Instruction {
                    opcode: polio::OpCodeT::OpSetFlag as i32,
                    args: vec![polio::Argument {
                        arg: Some(polio::argument::Arg::Flagval(polio::FlagT::FVsDock as i32)),
                    }],
                };
                proc.push(set_flag);
            }
        }

        polio::Proc { proc }
    }

    fn get_canonical_service_name(&mut self, svc_id: &str) -> String {
        if let Some(mangled) = self.name_mangler.get(svc_id) {
            return mangled.clone();
        }
        let mut mangled_sid = svc_id.replace(" ", "_");
        while self.name_mangler.contains_key(&mangled_sid) {
            mangled_sid = format!("{}_", mangled_sid); // append trailing underscore until unique
        }
        self.name_mangler
            .insert(svc_id.to_string(), mangled_sid.clone());
        mangled_sid
    }

    /// Convert a list of our Attributes structs into a list of the protocol buffer AttrExprs.
    fn attr_list_to_attrexpr(&self, attrs: &Vec<Attribute>) -> Vec<polio::AttrExpr> {
        let mut attrexpr = Vec::new();
        for a in attrs {
            let key = a.zpl_key();
            let val = a.zpl_value();
            let key_idx = self
                .policy
                .attr_key_index
                .iter()
                .position(|x| *x == key)
                .unwrap();
            let val_idx = self
                .policy
                .attr_val_index
                .iter()
                .position(|x| *x == val)
                .unwrap();
            attrexpr.push(polio::AttrExpr {
                key: key_idx as u32,
                op: if val.is_empty() {
                    polio::AttrOpT::Has as i32
                } else {
                    polio::AttrOpT::Eq as i32
                },
                val: val_idx as u32,
            });
        }
        attrexpr
    }

    /// Given the map table that has Entry->Index, convert into a vector
    /// such that vec[index] = entry.
    fn index_from_table(&self, table: &HashMap<String, usize>) -> Vec<String> {
        let mut idx = Vec::new();
        idx.resize(table.len(), "".to_string());
        for (k, v) in table {
            idx[*v] = k.clone();
        }
        idx
    }

    // Helper function that can create our lookup table that maps
    // keys or attributes to indexes.
    //
    // See [PolicyBuilder::populate_key_table] and [PolicyBuilder::populate_value_table].
    fn populate_lookup_table(
        &self,
        fabric: &Fabric,
        table: &mut HashMap<String, usize>,
        extraction_f: fn(&Attribute) -> String,
    ) {
        for s in &fabric.services {
            for a in &s.provider_attrs {
                let key = extraction_f(a);
                if !table.contains_key(&key) {
                    table.insert(key, table.len());
                }
            }
            for policy in &s.client_policies {
                for attr_vec in [&policy.cli_condition, &policy.svc_condition] {
                    for a in attr_vec {
                        let key = extraction_f(a);
                        if !table.contains_key(&key) {
                            table.insert(key, table.len());
                        }
                    }
                }
            }
        }
        for n in &fabric.nodes {
            for a in &n.provider_attrs {
                let key = extraction_f(a);
                if !table.contains_key(&key) {
                    table.insert(key, table.len());
                }
            }
        }
    }

    /// Create a table of all unique attribute keys.
    fn populate_key_table(&self, fabric: &Fabric, table: &mut HashMap<String, usize>) {
        self.populate_lookup_table(fabric, table, |a| a.zpl_key());
    }

    /// Create a table of all unique attribute values.
    fn populate_value_table(&self, fabric: &Fabric, table: &mut HashMap<String, usize>) {
        self.populate_lookup_table(fabric, table, |a| a.zpl_value());
    }

    /// Helper function that adds to the [polio::Policy::connects] list only if the
    /// `connect` is not already in the list.
    ///
    /// If connect is already there but does not have a PROC set, and the passed `connect`
    /// does, then we update the proc in the policy.
    fn add_connect(&mut self, connect: polio::Connect) {
        let attrs_hash = connect_to_hash(&connect);
        if self.connects_table.contains_key(&attrs_hash) {
            let idx = self.connects_table[&attrs_hash];
            if self.policy.connects[idx].proc == connect.proc {
                return; // dupe
            }
            if self.policy.connects[idx].proc == NO_PROC {
                // just update the proc (was blank)
                self.policy.connects[idx].proc = connect.proc;
                return;
            }
            if connect.proc == NO_PROC {
                // just keep the existing proc, no need for an addition line.
                return;
            }
            // else we need to insert
        }
        self.connects_table
            .insert(attrs_hash, self.policy.connects.len());
        self.policy.connects.push(connect);
    }
}

/// Generate some generic metadata.
fn metadata(pdate: &str) -> String {
    let username = env::var("USER").unwrap_or_else(|_| "(anonymous)".to_string());
    format!(
        "compiled {} on {} by {}",
        pdate,
        platform::gethostname(),
        username
    )
}

/// Given the policy connects vec which is a list of attributes, convert that into
/// a string that represents the attributes such that same set of attributs always
/// returns the same string.  We use this to prevent adding duplicates to the connects
/// list.
fn connect_to_hash(connect: &polio::Connect) -> String {
    // First convert the attr list into a list of u64 numbers
    let mut attrs: Vec<u64> = Vec::new();
    for ae in &connect.attr_exprs {
        let mut combined = match ae.op() {
            polio::AttrOpT::Eq | polio::AttrOpT::Unused => 0,
            polio::AttrOpT::Ne => 0x80 << 56,       // 10..
            polio::AttrOpT::Has => 0x40 << 56,      // 01..
            polio::AttrOpT::Excludes => 0xc0 << 56, // 11..
        };
        combined |= (((ae.key & 0x3FFFFFFF) as u64) << 32) | (ae.val as u64);
        attrs.push(combined);
    }

    // Then sort the numbers and convert to string.
    attrs.sort();
    let mut hash = String::new();
    for a in attrs {
        hash.push_str(&format!("{:x}", a));
    }
    hash
}

mod platform {

    #[cfg(target_family = "unix")]
    use nix::unistd;

    #[cfg(target_family = "unix")]
    pub fn gethostname() -> String {
        match unistd::gethostname() {
            Ok(h) => h.to_string_lossy().to_string(),
            Err(_) => "(unknown)".to_string(),
        }
    }

    #[cfg(not(target_family = "unix"))]
    pub fn gethostname() -> String {
        return "(unknown)".to_string();
    }
}
