use ::polio::policy_capnp;
use std::collections::HashMap;

use crate::compiler::get_compiler_version;
use crate::errors::CompilationError;
use crate::fabric::ServiceType; // TODO: remove refs to fabric
use crate::policywriter::{PFlags, PolicyContainer, PolicyWriter, TSType};
use crate::protocols::{IcmpFlowType, Protocol};
use crate::ptypes::Attribute; // TODO: remove refs to fabric

#[derive(Default)]
pub struct PolicyBinaryV2 {
    created_timestamp: String,
    policy_version: u64,
    policy_metadata: String,
    communication_policies: Vec<CommunicationPolicy>,
}

#[allow(dead_code)]
struct CommunicationPolicy {
    svc_id: String,
    policy_num: usize,
    protocol: Protocol,
    allow: bool,
    cli_conditions: Vec<Attribute>,
    svc_conditions: Vec<Attribute>,
}

#[derive(PartialEq, Eq)]
#[allow(dead_code)]
enum ScopeFlag {
    UdpOneWay,
    IcmpRequestReply,
}
struct Scope {
    protocol: u8,
    flag: Option<ScopeFlag>,
    port: Option<u16>,
    port_range: Option<(u16, u16)>,
}

#[derive(Default)]
pub struct PolicyContainerV2 {}

impl PolicyBinaryV2 {
    pub fn new() -> PolicyBinaryV2 {
        PolicyBinaryV2::default()
    }

    fn protocol_to_scopes(&self, svc_prot: &Protocol) -> Vec<Scope> {
        let mut scopes = Vec::new();
        // The service "protocol" struct is a bit poorly defined. But in general
        // if the protocol is ICMP then port can be ignored and we get the codes
        // from the icmp enum.  Otherwise we need to parse port. The port spec
        // idea from earlier ZPL is not implemented either, so the only thing
        // we accept in the port field is a single port number.
        if let Some(icmpflow) = svc_prot.get_icmp() {
            match icmpflow {
                IcmpFlowType::OneShot(icmp_types) => {
                    for icmp_type in icmp_types {
                        let scope = Scope {
                            protocol: svc_prot.get_layer4() as u8,
                            flag: None,
                            port: Some(*icmp_type as u16),
                            port_range: None,
                        };
                        scopes.push(scope);
                    }
                }
                IcmpFlowType::RequestResponse(req, rep) => {
                    let scope = Scope {
                        protocol: svc_prot.get_layer4() as u8,
                        flag: Some(ScopeFlag::IcmpRequestReply),
                        port: None,
                        port_range: Some((*req as u16, *rep as u16)),
                    };
                    scopes.push(scope);
                }
            }
        } else {
            let portnum: u16 = svc_prot.get_port().unwrap().parse().unwrap();
            let scope = Scope {
                protocol: svc_prot.get_layer4() as u8,
                flag: None,
                port: Some(portnum),
                port_range: None,
            };
            scopes.push(scope);
        }
        scopes
    }

    fn write_attributes(
        &self,
        attrs: &[Attribute],
        conds: &mut capnp::struct_list::Builder<'_, polio::policy_capnp::attr_expr::Owned>,
    ) {
        for (j, clicond) in attrs.iter().enumerate() {
            let mut ccond = conds.reborrow().get(j as u32);
            // foo:fee    (foo, eq, fee)
            // foo:       (foo, has, "")
            ccond.set_key(&clicond.zpl_key());
            let val = clicond.zpl_value();
            if val.is_empty() {
                ccond.set_op(policy_capnp::AttrOp::Has);
            } else {
                ccond.set_op(policy_capnp::AttrOp::Eq);
            }
            // The v2 policy is prepared for multi-valued attrs but we don't use that yet.
            let mut vals = ccond.init_value(1);
            vals.set(0, &val);
        }
    }
}

impl PolicyContainer for PolicyContainerV2 {
    fn contain_policy(
        &self,
        policy_data: Vec<u8>,
        signature: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CompilationError> {
        let mut container_msg = Box::new(::capnp::message::Builder::new_default());
        let mut container = container_msg.init_root::<policy_capnp::policy_container::Builder>();
        let (major, minor, patch) = get_compiler_version();
        container.set_zplc_ver_major(major);
        container.set_zplc_ver_minor(minor);
        container.set_zplc_ver_patch(patch);
        container.set_policy(policy_data.as_slice());
        if let Some(sig) = signature {
            container.set_signature(sig.as_slice());
        };
        let mut container_bytes: Vec<u8> = Vec::new();
        match capnp::serialize::write_message(&mut container_bytes, &container_msg) {
            Err(e) => {
                return Err(CompilationError::EncodingError(format!(
                    "failed to serialize policy container: {}",
                    e
                )));
            }
            Ok(_) => {}
        }
        Ok(container_bytes)
    }
}

// Note that this is only partically implemented to support the small amount of
// V2 functionality we need right now.
impl PolicyWriter for PolicyBinaryV2 {
    fn write_created_timestamp(&mut self, timestamp: &str) {
        self.created_timestamp = timestamp.to_string();
    }
    fn write_policy_version(&mut self, version: u64) {
        self.policy_version = version;
    }
    fn write_policy_revision(&mut self, _revision: &str) {
        // nop
    }
    fn write_policy_metadata(&mut self, metadata: &str) {
        self.policy_metadata = metadata.to_string();
    }
    fn write_max_visa_lifetime(&mut self, _lifetime: std::time::Duration) {
        // nop
    }
    fn write_attribute_tables(
        &mut self,
        _key_table: &HashMap<String, usize>,
        _value_table: &HashMap<String, usize>,
    ) {
        // nop
    }
    fn write_connect_match(&mut self, _conditions: &[Attribute]) {
        // nop
    }
    fn write_connect_match_for_provider(
        &mut self,
        _svc_attrs: &[Attribute],
        _svc_id: &str,
        _stype: &ServiceType,
        _endpoint: &str,
        _flags: Option<PFlags>,
    ) {
        // nop
    }
    fn write_service_cert(&mut self, _svc_id: &str, _cert_data: &[u8]) {
        // nop
    }
    fn write_bootstrap_key(&mut self, _cn: &str, _keydata: &[u8]) {
        // nop
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
        self.communication_policies.push(CommunicationPolicy {
            svc_id: svc_id.to_string(),
            policy_num,
            protocol: protocol.clone(),
            allow,
            cli_conditions: cli_conditions.to_vec(),
            svc_conditions: svc_conditions.to_vec(),
        });
    }
    fn write_trusted_service(
        &mut self,
        _svc_id: &str,
        _ts_type: TSType,
        _query_uri: Option<&str>,
        _validate_uri: Option<&str>,
        _returns_attrs: Option<&Vec<String>>,
        _identity_attrs: Option<&Vec<String>>,
    ) {
        // nop
    }
    fn print_stats(&self) {
        println!(
            "  {} communication policies",
            self.communication_policies.len()
        );
    }
    fn finalize(&mut self) -> Result<Vec<u8>, CompilationError> {
        // TODO - The capnp serialization needs writable memory buffer which I was unable to
        // figure out how to incrementally update then then "finalize" ... so we do everything
        // here using the state we built up.
        let mut policy_msg = ::capnp::message::Builder::new_default();
        let mut policy = policy_msg.init_root::<policy_capnp::policy::Builder>();

        policy.set_created(&self.created_timestamp);
        policy.set_version(self.policy_version);
        policy.set_metadata(&self.policy_metadata);

        // HMM: since you need to init these arrays before using it may be hard to incrementally
        // build the message.  So this state copy thing may be our only way to go.
        let mut cpols = policy.init_com_policies(self.communication_policies.len() as u32);
        for (i, cp) in self.communication_policies.iter().enumerate() {
            let scopes = self.protocol_to_scopes(&cp.protocol);
            let mut cpol = cpols.reborrow().get(i as u32);
            cpol.set_id(&cp.svc_id);
            cpol.set_service_id(&cp.svc_id);
            cpol.set_zpl("zpl_missing");
            cpol.set_allow(cp.allow);
            let mut cscopes = cpol.reborrow().init_scope(scopes.len() as u32);
            for (j, scope) in scopes.iter().enumerate() {
                let mut cscope = cscopes.reborrow().get(j as u32);
                cscope.set_protocol(scope.protocol);
                match scope.flag {
                    Some(ScopeFlag::UdpOneWay) => {
                        cscope.set_flag(policy_capnp::ScopeFlag::UdpOneWay);
                    }
                    Some(ScopeFlag::IcmpRequestReply) => {
                        cscope.set_flag(policy_capnp::ScopeFlag::IcmpRequestRepl);
                    }
                    None => {
                        cscope.set_flag(policy_capnp::ScopeFlag::NoFlag);
                    }
                }
                if let Some((low, hi)) = &scope.port_range {
                    let mut prange = cscope.init_port_range();
                    prange.set_low(*low);
                    prange.set_high(*hi);
                } else if let Some(p) = &scope.port {
                    let mut pnum = cscope.init_port();
                    pnum.set_port_num(*p);
                } else {
                    panic!("scope must have either port or port_range");
                }
            }
            let mut cliconds = cpol
                .reborrow()
                .init_client_conds(cp.cli_conditions.len() as u32);
            self.write_attributes(&cp.cli_conditions, &mut cliconds);
            let mut svcconds = cpol
                .reborrow()
                .init_service_conds(cp.svc_conditions.len() as u32);
            self.write_attributes(&cp.svc_conditions, &mut svcconds);
        }

        let mut policy_bytes: Vec<u8> = Vec::new();
        match capnp::serialize::write_message(&mut policy_bytes, &policy_msg) {
            Err(e) => {
                return Err(CompilationError::EncodingError(format!(
                    "failed to serialize policy: {}",
                    e
                )));
            }
            Ok(_) => {}
        }
        Ok(policy_bytes)
    }
}
