use std::collections::HashMap;

use polio::polio;
use prost::Message;

use crate::compiler::get_compiler_version;
use crate::errors::CompilationError;
use crate::fabric::ServiceType; // TODO: remove refs to fabric
use crate::policywriter::{PFlags, PolicyContainer, PolicyWriter, TSType};
use crate::protocols::{IcmpFlowType, Protocol};
use crate::ptypes::Attribute;
use crate::zpl;

/// This value for a PROC in a connect record means NO PROC.  Binary format v1.
pub const NO_PROC: u32 = u32::MAX; // 0xffffffff

#[derive(Default)]
pub struct PolicyBinaryV1 {
    policy: polio::Policy,
    connects_table: HashMap<String, usize>, // connect hash string -> connect index
}

/// The old prototype visa service binary policy format container.
#[derive(Default)]
pub struct PolicyContainerV1 {}

impl PolicyContainer for PolicyContainerV1 {
    fn contain_policy(
        &self,
        pol_buf: Vec<u8>,
        signature: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CompilationError> {
        // We need to de-serialize the policy to get some of the header fields.
        let pol: polio::Policy =
            polio::Policy::decode(pol_buf.as_slice()).expect("failed to decode binary policy file");

        let (major, minor, patch) = get_compiler_version();

        let sig_or_empty = match signature {
            Some(s) => s,
            None => Vec::new(),
        };

        let container = polio::PolicyContainer {
            version_major: major,
            version_minor: minor,
            version_patch: patch,
            policy_date: pol.policy_date.clone(),
            policy_version: pol.policy_version,
            policy_revision: pol.policy_revision.clone(),
            policy_metadata: pol.policy_metadata.clone(),
            policy: pol_buf,
            signature: sig_or_empty,
        };
        let mut buf = Vec::with_capacity(container.encoded_len());
        container.encode(&mut buf).map_err(|e| {
            CompilationError::EncodingError(format!("failed to encode policy container: {}", e))
        })?;
        Ok(buf)
    }
}

/// The old prototype visa service binary policy format.
impl PolicyBinaryV1 {
    pub fn new() -> PolicyBinaryV1 {
        PolicyBinaryV1::default()
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

    /// Convert a list of our Attributes structs into a list of the protocol buffer AttrExprs.
    fn attr_list_to_attrexpr(&self, attrs: &[Attribute]) -> Vec<polio::AttrExpr> {
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

    /// Helper function that adds to the [polio::Policy::connects] list only if the
    /// `connect` is not already in the list.
    ///
    /// If connect is already there but does not have a PROC set, and the passed `connect`
    /// does, then we update the proc in the policy.
    fn add_connect(&mut self, connect: polio::Connect) {
        let attrs_hash = self.connect_to_hash(&connect);
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

    /// Given the policy connects vec which is a list of attributes, convert that into
    /// a string that represents the attributes such that same set of attributs always
    /// returns the same string.  We use this to prevent adding duplicates to the connects
    /// list.
    fn connect_to_hash(&self, connect: &polio::Connect) -> String {
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

    /// Create a PROC for the policy binary to register a service and optionally set flags.
    /// `endpoint_str` is comma separated list of endpoint values.
    fn create_service_proc(
        &mut self,
        canonical_svc_id: &str,
        svc_type: &ServiceType,
        endpoint_str: &str,
        flags: Option<PFlags>,
    ) -> polio::Proc {
        let mut proc = Vec::new();

        // Args for register are (NAME:String, Type:SvcT, ENDPOINTS:String)
        let mut args = Vec::new();

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

    /// Create a polio::Scope from a FabricService.protocol.
    /// Only services with protocols should be passed here.
    ///
    /// Will panic if there are any errors -- all error checking should have
    /// been done earlier.
    fn scope_for_protocol(&self, svc_prot: &Protocol) -> Vec<polio::Scope> {
        let mut scopes = Vec::new();

        // The visa service and policy protobuf support a much richer protcol description than
        // we do in our current ZPL parser.  The current ZPL supports one protocol and one port
        // per service.

        let parg: polio::scope::Protarg;

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
                                panic!("service with invalid port number: {}", port_str);
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
                        panic!("service protocol must be ICMP or have a valid port");
                    }
                }
            }
        }

        let scope = polio::Scope {
            protocol: svc_prot.get_layer4().into(),
            protarg: Some(parg),
        };
        scopes.push(scope);
        scopes
    }
}

impl PolicyWriter for PolicyBinaryV1 {
    fn write_created_timestamp(&mut self, timestamp: &str) {
        self.policy.policy_date = timestamp.to_string();
    }
    fn write_policy_version(&mut self, version: u64) {
        self.policy.policy_version = version;
    }
    fn write_policy_revision(&mut self, revision: &str) {
        self.policy.policy_revision = revision.to_string();
    }
    fn write_policy_metadata(&mut self, metadata: &str) {
        self.policy.policy_metadata = metadata.to_string();
    }
    fn write_max_visa_lifetime(&mut self, lifetime: std::time::Duration) {
        let cs = polio::ConfigSetting {
            key: zpl::CONFIG_KEY_MAX_VISA_LIFETIME,
            val: Some(polio::config_setting::Val::U64v(lifetime.as_secs())),
        };
        self.policy.config.push(cs);
    }
    fn write_attribute_tables(
        &mut self,
        key_table: &HashMap<String, usize>,
        value_table: &HashMap<String, usize>,
    ) {
        self.policy.attr_key_index = self.index_from_table(key_table);
        self.policy.attr_val_index = self.index_from_table(value_table);
    }
    fn write_connect_match(&mut self, conditions: &[Attribute]) {
        let pconnect = polio::Connect {
            attr_exprs: self.attr_list_to_attrexpr(conditions),
            proc: NO_PROC,
        };
        self.add_connect(pconnect);
    }
    fn write_connect_match_for_provider(
        &mut self,
        svc_attrs: &[Attribute],
        svc_id: &str,
        stype: &ServiceType,
        endpoint: &str,
        flags: Option<PFlags>,
    ) {
        let proc = self.create_service_proc(svc_id, stype, endpoint, flags);
        self.policy.procs.push(proc);
        let proc_idx = self.policy.procs.len() as u32 - 1;
        let pconnect = polio::Connect {
            attr_exprs: self.attr_list_to_attrexpr(svc_attrs),
            proc: proc_idx,
        };
        self.add_connect(pconnect);
    }
    fn write_service_cert(&mut self, svc_id: &str, cert_data: &[u8]) {
        let pcert = polio::Cert {
            id: self.policy.certificates.len() as u32 + 1, // note: we do not use ID of 0
            asn1data: cert_data.to_vec(),
            name: svc_id.to_string(),
        };
        self.policy.certificates.push(pcert);
    }
    fn write_cpolicy(
        &mut self,
        svc_id: &str,
        policy_num: usize,
        protocol: &Protocol,
        allow: bool,
        cli_conditions: &[Attribute],
        svc_conditions: &[Attribute],
    ) {
        let pscope = self.scope_for_protocol(protocol);
        let mut cpol = polio::CPolicy {
            service_id: svc_id.into(),
            id: svc_id.into(), // TODO: Not sure why we have both id and service_id.
            scope: pscope.clone(),
            cli_conditions: Vec::new(),
            svc_conditions: Vec::new(),
            constraints: Vec::new(), // TODO
            allow,
        };
        if !cli_conditions.is_empty() {
            let exprs = self.attr_list_to_attrexpr(cli_conditions);
            let cond = polio::Condition {
                // TODO: In old ZPL we copied down the docstring from the ZPL into this ID.
                id: format!("{}-{}c", svc_id, policy_num),
                attr_exprs: exprs,
            };
            cpol.cli_conditions.push(cond);
        }
        if !svc_conditions.is_empty() {
            let exprs = self.attr_list_to_attrexpr(svc_conditions);
            let cond = polio::Condition {
                // TODO: In old ZPL we copied down the docstring from the ZPL into this ID.
                id: format!("{}-{}s", svc_id, policy_num),
                attr_exprs: exprs,
            };
            cpol.svc_conditions.push(cond);
        }
        self.policy.policies.push(cpol);
    }

    fn write_bootstrap_key(&mut self, cn: &str, keydata: &[u8]) {
        self.policy.pubkeys.push(polio::PublicKey {
            cn: cn.to_string(),
            keydata: keydata.to_vec(),
        });
    }

    fn write_trusted_service(
        &mut self,
        svc_id: &str,
        ts_type: TSType,
        query_uri: Option<&str>,
        validate_uri: Option<&str>,
        returns_attrs: Option<&Vec<String>>,
        identity_attrs: Option<&Vec<String>>,
    ) {
        let query_uri = match query_uri {
            Some(q) => q,
            None => "",
        };

        let validate_uri = match validate_uri {
            Some(v) => v,
            None => "",
        };

        let attrs = match returns_attrs {
            Some(a) => a.clone(),
            None => Vec::new(),
        };

        let id_attrs = match identity_attrs {
            Some(a) => a.clone(),
            None => Vec::new(),
        };

        let polio_ts_t = match ts_type {
            TSType::VsAuth => polio::SvcT::SvctAuth,
            TSType::ActorAuth => polio::SvcT::SvctActorAuth,
        };

        let trusted_svc = polio::Service {
            r#type: polio_ts_t.into(),
            name: svc_id.into(),
            prefix: svc_id.into(),
            domain: String::new(),
            query_uri: query_uri.into(),
            validate_uri: validate_uri.into(),
            attrs: attrs,
            id_attrs: id_attrs,
        };
        self.policy.services.push(trusted_svc);
    }

    fn print_stats(&self) {
        println!("  {} connect rules", self.policy.connects.len());
        println!("  {} trusted services", self.policy.services.len());
        println!("  {} communication policies", self.policy.policies.len());
        println!(
            "  {} attr keys / {} attr values",
            self.policy.attr_key_index.len() - 1,
            self.policy.attr_val_index.len() - 1
        );
    }

    fn finalize(&mut self) -> Result<Vec<u8>, CompilationError> {
        let mut buf = Vec::with_capacity(self.policy.encoded_len());
        self.policy.encode(&mut buf).map_err(|e| {
            CompilationError::EncodingError(format!("failed to encode policy: {}", e))
        })?;
        Ok(buf)
    }
}
