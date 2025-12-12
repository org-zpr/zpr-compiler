use openssl::sha;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use zpr::policy::v1 as policy_capnp;

use crate::compiler::get_compiler_version;
use crate::errors::CompilationError;
use crate::fabric::ServiceType; // TODO: remove refs to fabric
use crate::policywriter::{PFlags, PolicyContainer, PolicyWriter, TSType};
use crate::protocols::{IcmpFlowType, PortSpec, Protocol, ProtocolDetails};
use crate::ptypes::{Attribute, Signal}; // TODO: remove refs to fabric

#[derive(Default)]
pub struct PolicyBinaryV2 {
    created_timestamp: String,
    policy_version: u64,
    policy_metadata: String,
    communication_policies: Vec<CommunicationPolicy>,
    bootstrap_keys: Vec<BootstrapKey>,
    join_policies: JPBuilder,
}

#[allow(dead_code)]
struct CommunicationPolicy {
    svc_id: String,
    policy_num: usize,
    protocol: Protocol,
    allow: bool,
    cli_conditions: Vec<Attribute>,
    svc_conditions: Vec<Attribute>,
    pline: String,
    signal: Option<Signal>,
}

struct BootstrapKey {
    cn: String,
    keydata: Vec<u8>,
}

/// This scope flag mirrors what is in the capnp schema.
#[derive(PartialEq, Eq, Debug)]
#[allow(dead_code)]
enum ScopeFlag {
    UdpOneWay,
    IcmpRequestReply,
}

/// This struct mirrors what is in the capnp schema.
struct Scope {
    protocol: u8,
    flag: Option<ScopeFlag>,
    port: Option<u16>,
    port_range: Option<(u16, u16)>,
}

#[derive(Default)]
struct JPBuilder {
    policies: HashMap<JPKey, JoinPolicy>,
}

struct JoinPolicy {
    conditions: Vec<Attribute>,
    flags: PFlags,
    provides: Option<Vec<Service>>,
}

struct Service {
    id: String,
    endpoints: Vec<Endpoint>,
    kind: ServiceType,
}

// Each endpoint is a protocol then either a RANGE or one or more numbers.
struct Endpoint {
    protocol: u8,
    ports: PbPortSpec,
    icmp_ft: Option<PbIcmpFlowType>,
}

enum PbPortSpec {
    Ports(Vec<u16>),
    Range(u16, u16), // not used for ICMP
}

enum PbIcmpFlowType {
    ReqResp,
    OneShot,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct JPKey {
    hashval: String,
}

impl Endpoint {
    // TODO: unit tests!!
    fn new_from_protocol(prot: &Protocol) -> Vec<Self> {
        let mut endpoints = Vec::new();

        match prot.get_details() {
            ProtocolDetails::TcpUdp(portspecs) => {
                let mut ports = Vec::new();
                for spec in portspecs {
                    match spec {
                        PortSpec::Range(low, high) => endpoints.push(Endpoint {
                            protocol: prot.get_layer4() as u8,
                            ports: PbPortSpec::Range(*low, *high),
                            icmp_ft: None,
                        }),
                        PortSpec::Single(port) => {
                            ports.push(*port);
                        }
                    }
                }
                if !ports.is_empty() {
                    endpoints.push(Endpoint {
                        protocol: prot.get_layer4() as u8,
                        ports: PbPortSpec::Ports(ports),
                        icmp_ft: None,
                    });
                }
            }
            ProtocolDetails::Icmp(flow) => match flow {
                IcmpFlowType::OneShot(codes) => {
                    endpoints.push(Endpoint {
                        protocol: prot.get_layer4() as u8,
                        ports: PbPortSpec::Ports(codes.iter().map(|&c| c as u16).collect()),
                        icmp_ft: Some(PbIcmpFlowType::OneShot),
                    });
                }
                IcmpFlowType::RequestResponse(req, resp) => {
                    endpoints.push(Endpoint {
                        protocol: prot.get_layer4() as u8,
                        ports: PbPortSpec::Ports(vec![*req as u16, *resp as u16]),
                        icmp_ft: Some(PbIcmpFlowType::ReqResp),
                    });
                }
            },
        }
        endpoints
    }
}

impl JPBuilder {
    fn has(&self, conditions: &[Attribute]) -> bool {
        let key = JPKey::new(conditions);
        self.policies.contains_key(&key)
    }

    fn add_connect(&mut self, conditions: &[Attribute]) {
        let key = JPKey::new(conditions);
        let jp = JoinPolicy {
            conditions: conditions.to_vec(),
            flags: PFlags::default(),
            provides: None,
        };
        self.policies.insert(key, jp);
    }

    // Note that same attr set may provide multiple services.
    // flags are additive.
    fn add_provides(&mut self, conditions: &[Attribute], service: Service, flags: Option<PFlags>) {
        let key = JPKey::new(conditions);
        if let Some(jp) = self.policies.get_mut(&key) {
            // We already have a policy, so add this service and flags.
            if let Some(new_flags) = flags {
                jp.flags.or(new_flags);
            }
            if let Some(existing_provides) = jp.provides.as_mut() {
                existing_provides.push(service);
            } else {
                jp.provides = Some(vec![service]);
            }
        } else {
            // Not in our table yet.
            let mut jp = JoinPolicy {
                conditions: conditions.to_vec(),
                flags: PFlags::default(),
                provides: Some(vec![service]),
            };
            if let Some(new_flags) = flags {
                jp.flags.or(new_flags);
            }
            self.policies.insert(key, jp);
        }
    }
}

impl JPKey {
    fn new(conditions: &[Attribute]) -> Self {
        // To create the hash we use ordered list of keys, then canonical reps of the attributes.
        let mut table = HashMap::new();
        let mut sorted_keys = Vec::new();
        for attr in conditions {
            let k = attr.zpl_key();

            let vals = attr.zpl_values();
            let op_code = if vals.is_empty() || vals[0].is_empty() || attr.is_multi_valued() {
                "has"
            } else {
                "eq"
            };

            let attr_str = format!("{op_code}: {}", &vals.join(","));

            if let Some(_duplicate) = table.insert(k.clone(), attr_str) {
                panic!("duplicate attribute found in join conditions: {k}",);
            }
            sorted_keys.push(k);
        }
        sorted_keys.sort();

        let mut hasher = sha::Sha256::new();
        for key in sorted_keys {
            if let Some(val) = table.get(&key) {
                hasher.update(key.as_bytes());
                hasher.update(val.as_bytes());
            }
        }
        let hashval = format!("{}", hex::encode(hasher.finish()));
        JPKey { hashval }
    }
}

/// The V2 binary policy container.
#[derive(Default)]
pub struct PolicyContainerV2 {}

/// The V2 binary policy format.
impl PolicyBinaryV2 {
    pub fn new() -> PolicyBinaryV2 {
        PolicyBinaryV2::default()
    }

    /// Take a service protocol and store it as capnp "Scopes"
    fn protocol_to_scopes(&self, svc_prot: &Protocol) -> Vec<Scope> {
        let mut scopes = Vec::new();
        // The service "protocol" struct is a bit poorly defined. But in general
        // if the protocol is ICMP then port can be ignored and we get the codes
        // from the icmp enum.  Otherwise we need to parse port. The port spec
        // idea from earlier ZPL is not implemented either, so the only thing
        // we accept in the port field is a single port number.

        match svc_prot.get_details() {
            ProtocolDetails::Icmp(ft) => match ft {
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
            },
            ProtocolDetails::TcpUdp(specs) => {
                for spec in specs {
                    let scope = match spec {
                        PortSpec::Single(pnum) => Scope {
                            protocol: svc_prot.get_layer4() as u8,
                            flag: None,
                            port: Some(*pnum),
                            port_range: None,
                        },
                        PortSpec::Range(lo, hi) => Scope {
                            protocol: svc_prot.get_layer4() as u8,
                            flag: None,
                            port: None,
                            port_range: Some((*lo, *hi)),
                        },
                    };
                    scopes.push(scope);
                }
            }
        }
        scopes
    }

    /// Helper to write attributes into capnp AttrExpr list.
    /// We have to do this for client conditions and service conditions.
    fn write_attributes(
        &self,
        attrs: &[Attribute],
        conds: &mut capnp::struct_list::Builder<'_, policy_capnp::attr_expr::Owned>,
    ) {
        for (j, attr) in attrs.iter().enumerate() {
            let mut ccond = conds.reborrow().get(j as u32);
            // foo:fee    (foo, eq, fee)
            // foo:       (foo, has, "")
            ccond.set_key(&attr.zpl_key());
            let vals = attr.zpl_values();

            if vals.is_empty() || vals[0].is_empty() || attr.is_multi_valued() {
                ccond.set_op(policy_capnp::AttrOp::Has);
            } else {
                ccond.set_op(policy_capnp::AttrOp::Eq);
            }
            let mut cvals = ccond.init_value(vals.len() as u32);
            for (i, val) in vals.iter().enumerate() {
                cvals.set(i as u32, val);
            }
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

    fn write_connect_match(&mut self, conditions: &[Attribute]) {
        if !self.join_policies.has(conditions) {
            self.join_policies.add_connect(conditions);
        }
    }

    fn write_connect_match_for_provider(
        &mut self,
        svc_attrs: &[Attribute],
        svc_id: &str,
        stype: &ServiceType,
        endpoint: &Protocol,
        flags: Option<PFlags>,
    ) {
        let endpoints = Endpoint::new_from_protocol(endpoint);
        let service = Service {
            id: svc_id.into(),
            endpoints,
            kind: stype.clone(),
        };
        self.join_policies.add_provides(svc_attrs, service, flags);
    }

    fn write_service_cert(&mut self, _svc_id: &str, _cert_data: &[u8]) {
        // nop
    }

    fn write_bootstrap_key(&mut self, _cn: &str, _keydata: &[u8]) {
        self.bootstrap_keys.push(BootstrapKey {
            cn: _cn.to_string(),
            keydata: _keydata.to_vec(),
        });
    }

    fn write_cpolicy(
        &mut self,
        svc_id: &str,
        policy_num: usize,
        protocol: &Protocol,
        allow: bool,
        cli_conditions: &[Attribute],
        svc_conditions: &[Attribute],
        signal: Option<Signal>,
        pline: &str,
    ) {
        self.communication_policies.push(CommunicationPolicy {
            svc_id: svc_id.to_string(),
            policy_num,
            protocol: protocol.clone(),
            allow,
            cli_conditions: cli_conditions.to_vec(),
            svc_conditions: svc_conditions.to_vec(),
            pline: pline.to_string(),
            signal,
        });
    }

    fn write_trusted_service(
        &mut self,
        _svc_id: &str,
        _ts_type: TSType,
        _query_uri: Option<&str>,
        _validate_uri: Option<&str>,
        _returns_attrs: Option<&HashMap<String, Attribute>>,
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

    fn finalize(self) -> Result<Vec<u8>, CompilationError> {
        let mut policy_msg = ::capnp::message::Builder::new_default();
        let mut policy = policy_msg.init_root::<policy_capnp::policy::Builder>();

        policy.set_created(&self.created_timestamp);
        policy.set_version(self.policy_version);
        policy.set_metadata(&self.policy_metadata);

        let mut bkeys = policy
            .reborrow()
            .init_keys(self.bootstrap_keys.len() as u32);
        for (i, bkey) in self.bootstrap_keys.iter().enumerate() {
            let mut km_builder = bkeys.reborrow().get(i as u32);

            km_builder.set_id(&bkey.cn);
            km_builder.set_key_type(policy_capnp::KeyMaterialT::RsaPub);

            let mut allows_builder = km_builder.reborrow().init_key_allows(1);
            allows_builder.set(0, policy_capnp::KeyAllowance::Bootstrap);

            km_builder.set_key_data(&bkey.keydata);
        }

        let mut cpols = policy.init_com_policies(self.communication_policies.len() as u32);
        for (i, cp) in self.communication_policies.iter().enumerate() {
            let scopes = self.protocol_to_scopes(&cp.protocol);
            let mut cpol = cpols.reborrow().get(i as u32);
            cpol.set_id(&cp.svc_id);
            cpol.set_service_id(&cp.svc_id);
            cpol.set_zpl(&cp.pline);
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

            if cp.signal.is_some() {
                let mut sig_build = cpol.reborrow().init_signal();
                sig_build
                    .reborrow()
                    .init_msg(cp.signal.as_ref().unwrap().message.len() as u32)
                    .push_str(&cp.signal.as_ref().unwrap().message);
                sig_build
                    .init_svc(cp.signal.as_ref().unwrap().service_class_name.len() as u32)
                    .push_str(&cp.signal.as_ref().unwrap().service_class_name);
            }
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocols::{IcmpFlowType, Protocol};

    #[test]
    fn test_protocol_to_scopes_basic_tcp() {
        let pb = PolicyBinaryV2::new();

        let prot1 = Protocol::tcp("foo")
            .add_port(PortSpec::Single(80))
            .build()
            .unwrap();
        let scopes1 = pb.protocol_to_scopes(&prot1);
        assert_eq!(scopes1.len(), 1);
        assert_eq!(scopes1[0].protocol, 6);
        assert_eq!(scopes1[0].port, Some(80));
        assert_eq!(scopes1[0].port_range, None);
        assert_eq!(scopes1[0].flag, None);
    }

    #[test]
    fn test_protocol_to_scopes_multiple_tcp() {
        let pb = PolicyBinaryV2::new();

        let prot1 = Protocol::tcp("foo")
            .add_ports(vec![
                PortSpec::Single(80),
                PortSpec::Single(443),
                PortSpec::Range(1000, 2000),
            ])
            .build()
            .unwrap();
        let scopes1 = pb.protocol_to_scopes(&prot1);
        assert_eq!(scopes1.len(), 3);
        assert_eq!(scopes1[0].protocol, 6);
        assert_eq!(scopes1[0].port, Some(80));
        assert_eq!(scopes1[0].port_range, None);
        assert_eq!(scopes1[0].flag, None);
        assert_eq!(scopes1[1].protocol, 6);
        assert_eq!(scopes1[1].port, Some(443));
        assert_eq!(scopes1[1].port_range, None);
        assert_eq!(scopes1[1].flag, None);
        assert_eq!(scopes1[2].protocol, 6);
        assert_eq!(scopes1[2].port, None);
        assert_eq!(scopes1[2].port_range, Some((1000, 2000)));
        assert_eq!(scopes1[2].flag, None);
    }

    #[test]
    fn test_protocol_to_scopes_icmp_request_reply() {
        let pb = PolicyBinaryV2::new();
        let flow = IcmpFlowType::RequestResponse(128, 129);
        let prot1 = Protocol::icmp6("foo", flow).build().unwrap();
        let scopes1 = pb.protocol_to_scopes(&prot1);
        assert_eq!(scopes1.len(), 1);
        assert_eq!(scopes1[0].protocol, 58);
        assert_eq!(scopes1[0].port, None);
        assert_eq!(scopes1[0].port_range, Some((128, 129)));
        assert_eq!(scopes1[0].flag, Some(ScopeFlag::IcmpRequestReply));
    }

    #[test]
    fn test_protocol_to_scopes_icmp_once() {
        let pb = PolicyBinaryV2::new();
        let flow = IcmpFlowType::OneShot(vec![128]);
        let prot1 = Protocol::icmp6("foo", flow).build().unwrap();
        let scopes1 = pb.protocol_to_scopes(&prot1);
        assert_eq!(scopes1.len(), 1);
        assert_eq!(scopes1[0].protocol, 58);
        assert_eq!(scopes1[0].port, Some(128));
        assert_eq!(scopes1[0].port_range, None);
        assert_eq!(scopes1[0].flag, None);
    }

    #[test]
    fn test_protocol_to_scopes_icmp_once_multiple() {
        let pb = PolicyBinaryV2::new();
        let flow = IcmpFlowType::OneShot(vec![128, 129, 130]);
        let prot1 = Protocol::icmp6("foo", flow).build().unwrap();
        let scopes1 = pb.protocol_to_scopes(&prot1);
        assert_eq!(scopes1.len(), 3);
        assert_eq!(scopes1[0].protocol, 58);
        assert_eq!(scopes1[0].port, Some(128));
        assert_eq!(scopes1[0].port_range, None);
        assert_eq!(scopes1[0].flag, None);
        assert_eq!(scopes1[1].protocol, 58);
        assert_eq!(scopes1[1].port, Some(129));
        assert_eq!(scopes1[1].port_range, None);
        assert_eq!(scopes1[1].flag, None);
        assert_eq!(scopes1[2].protocol, 58);
        assert_eq!(scopes1[2].port, Some(130));
        assert_eq!(scopes1[2].port_range, None);
        assert_eq!(scopes1[2].flag, None);
    }
}
