use openssl::sha;
use std::collections::HashMap;
use std::hash::Hash;
use zpr::policy::v1 as policy_capnp;

use crate::compiler::get_compiler_version;
use crate::errors::CompilationError;
use crate::policywriter::{PolicyContainer, PolicyWriter, TSType};
use crate::protocols::{IcmpFlowType, PortSpec, Protocol, ProtocolDetails};
use crate::ptypes::Signal;

use zpr::policy_types::{Attribute, PFlags};
use zpr::policy_types::{JoinPolicy, Scope, ScopeFlag};
use zpr::policy_types::{Service, ServiceType};
use zpr::policy_types::{WriteTo, write_attributes}; // TODO: remove refs to fabric

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

fn new_scope_from_protocol(prot: &Protocol) -> Vec<Scope> {
    let mut scopes = Vec::new();

    match prot.get_details() {
        ProtocolDetails::TcpUdp(portspecs) => {
            for spec in portspecs {
                match spec {
                    PortSpec::Range(low, high) => scopes.push(Scope {
                        protocol: prot.get_layer4() as u8,
                        flag: None,
                        port: None,
                        port_range: Some((*low, *high)),
                    }),
                    PortSpec::Single(port) => scopes.push(Scope {
                        protocol: prot.get_layer4() as u8,
                        flag: None,
                        port: Some(*port),
                        port_range: None,
                    }),
                }
            }
        }
        ProtocolDetails::Icmp(flow) => match flow {
            IcmpFlowType::OneShot(codes) => {
                for code in codes {
                    scopes.push(Scope {
                        protocol: prot.get_layer4() as u8,
                        flag: None,
                        port: Some(*code as u16),
                        port_range: None,
                    });
                }
            }
            IcmpFlowType::RequestResponse(req, resp) => {
                scopes.push(Scope {
                    protocol: prot.get_layer4() as u8,
                    flag: Some(ScopeFlag::IcmpRequestReply),
                    port: None,
                    port_range: Some((*req as u16, *resp as u16)),
                });
            }
        },
    }
    scopes
}

/// Organize our JoinPolicies as they are added to the policy.
#[derive(Default)]
struct JPBuilder {
    policies: HashMap<JPKey, JoinPolicy>,
}

/// JoinPolicy key value. We construct these so that a given set of attributes
/// maps to a unique key.
#[derive(Debug, PartialEq, Eq, Hash)]
struct JPKey {
    hashval: String,
}

impl JPBuilder {
    fn len(&self) -> usize {
        self.policies.len()
    }

    fn iter(&self) -> impl Iterator<Item = (&JPKey, &JoinPolicy)> {
        self.policies.iter()
    }

    /// TRUE if this building contains this exact attribute collection.
    fn has(&self, conditions: &[Attribute]) -> bool {
        let key = JPKey::new(conditions);
        self.policies.contains_key(&key)
    }

    /// Adds a connect join policy (no services provided) if not already present.
    fn add_connect(&mut self, conditions: &[Attribute]) {
        let key = JPKey::new(conditions);
        if !self.policies.contains_key(&key) {
            let jp = JoinPolicy {
                conditions: conditions.to_vec(),
                flags: PFlags::default(),
                provides: None,
            };
            self.policies.insert(key, jp);
        }
    }

    /// Add a connect join policy that also provides a service.
    /// Note that same attr set may provide multiple services.
    /// flags are additive.
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
    /// The JoinPolicy key is a unique identifier for a given set of attributes such that
    /// the same set of attributes always gets the same key.
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
        // assumption: service type is set.
        if stype == &ServiceType::Undefined {
            panic!("service cannot have undefined type");
        }
        let endpoints = new_scope_from_protocol(endpoint);
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

    /// For Capn Proto the write_xxx functions just build up an internal copy of the data
    /// until we call this function which serializes everything at once.
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

        let mut cpols = policy
            .reborrow()
            .init_com_policies(self.communication_policies.len() as u32);
        for (i, cp) in self.communication_policies.iter().enumerate() {
            let scopes = new_scope_from_protocol(&cp.protocol);
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
            write_attributes(&cp.cli_conditions, &mut cliconds);
            let mut svcconds = cpol
                .reborrow()
                .init_service_conds(cp.svc_conditions.len() as u32);
            write_attributes(&cp.svc_conditions, &mut svcconds);

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

        let mut jpols = policy.init_join_policies(self.join_policies.len() as u32);
        let mut jpidx = 0;
        for (_jp_key, jp) in self.join_policies.iter() {
            let mut jpol = jpols.reborrow().get(jpidx);
            jp.write_to(&mut jpol);
            jpidx += 1;
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
        let prot1 = Protocol::tcp("foo")
            .add_port(PortSpec::Single(80))
            .build()
            .unwrap();
        let scopes1 = new_scope_from_protocol(&prot1);
        assert_eq!(scopes1.len(), 1);
        assert_eq!(scopes1[0].protocol, 6);
        assert_eq!(scopes1[0].port, Some(80));
        assert_eq!(scopes1[0].port_range, None);
        assert_eq!(scopes1[0].flag, None);
    }

    #[test]
    fn test_protocol_to_scopes_multiple_tcp() {
        let prot1 = Protocol::tcp("foo")
            .add_ports(vec![
                PortSpec::Single(80),
                PortSpec::Single(443),
                PortSpec::Range(1000, 2000),
            ])
            .build()
            .unwrap();
        let scopes1 = new_scope_from_protocol(&prot1);
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
        let flow = IcmpFlowType::RequestResponse(128, 129);
        let prot1 = Protocol::icmp6("foo", flow).build().unwrap();
        let scopes1 = new_scope_from_protocol(&prot1);
        assert_eq!(scopes1.len(), 1);
        assert_eq!(scopes1[0].protocol, 58);
        assert_eq!(scopes1[0].port, None);
        assert_eq!(scopes1[0].port_range, Some((128, 129)));
        assert_eq!(scopes1[0].flag, Some(ScopeFlag::IcmpRequestReply));
    }

    #[test]
    fn test_protocol_to_scopes_icmp_once() {
        let flow = IcmpFlowType::OneShot(vec![128]);
        let prot1 = Protocol::icmp6("foo", flow).build().unwrap();
        let scopes1 = new_scope_from_protocol(&prot1);
        assert_eq!(scopes1.len(), 1);
        assert_eq!(scopes1[0].protocol, 58);
        assert_eq!(scopes1[0].port, Some(128));
        assert_eq!(scopes1[0].port_range, None);
        assert_eq!(scopes1[0].flag, None);
    }

    #[test]
    fn test_protocol_to_scopes_icmp_once_multiple() {
        let flow = IcmpFlowType::OneShot(vec![128, 129, 130]);
        let prot1 = Protocol::icmp6("foo", flow).build().unwrap();
        let scopes1 = new_scope_from_protocol(&prot1);
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

    #[test]
    fn test_scope_new_from_protocol_udp_mixed_ports() {
        let prot = Protocol::udp("svc")
            .add_ports(vec![
                PortSpec::Range(1000, 2000),
                PortSpec::Single(8080),
                PortSpec::Range(3000, 4000),
            ])
            .build()
            .unwrap();

        let scopes = new_scope_from_protocol(&prot);
        assert_eq!(scopes.len(), 3);

        match (&scopes[0].port, scopes[0].port_range) {
            (None, Some((lo, hi))) => assert_eq!((lo, hi), (1000, 2000)),
            _ => panic!("expected first scope to be a range"),
        }
        assert_eq!(scopes[0].protocol, prot.get_layer4() as u8);
        assert_eq!(scopes[0].flag, None);

        assert_eq!(scopes[1].port, Some(8080));
        assert_eq!(scopes[1].port_range, None);
        assert_eq!(scopes[1].protocol, prot.get_layer4() as u8);

        match (&scopes[2].port, scopes[2].port_range) {
            (None, Some((lo, hi))) => assert_eq!((lo, hi), (3000, 4000)),
            _ => panic!("expected third scope to be a range"),
        }
    }

    #[test]
    fn test_scope_new_from_protocol_icmp_one_shot_multiple_codes() {
        let prot = Protocol::icmp4("icmp", IcmpFlowType::OneShot(vec![1, 2, 3]))
            .build()
            .unwrap();

        let scopes = new_scope_from_protocol(&prot);
        assert_eq!(scopes.len(), 3);
        for (idx, expected) in [1u16, 2, 3].into_iter().enumerate() {
            assert_eq!(scopes[idx].protocol, prot.get_layer4() as u8);
            assert_eq!(scopes[idx].port, Some(expected));
            assert_eq!(scopes[idx].port_range, None);
            assert_eq!(scopes[idx].flag, None);
        }
    }

    #[test]
    fn test_scope_new_from_protocol_icmp_request_response_flag() {
        let prot = Protocol::icmp6("icmp", IcmpFlowType::RequestResponse(5, 6))
            .build()
            .unwrap();

        let scopes = new_scope_from_protocol(&prot);
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].protocol, prot.get_layer4() as u8);
        assert_eq!(scopes[0].port, None);
        assert_eq!(scopes[0].port_range, Some((5, 6)));
        assert_eq!(scopes[0].flag, Some(ScopeFlag::IcmpRequestReply));
    }

    #[test]
    fn test_jpkey_new_order_independent() {
        let attr_role = Attribute::tuple("user.role")
            .single()
            .value("admin")
            .build()
            .unwrap();
        let attr_tag = Attribute::tag("endpoint.hardened").build().unwrap();

        let key_a = JPKey::new(&[attr_role.clone(), attr_tag.clone()]);
        let key_b = JPKey::new(&[attr_tag, attr_role]);
        assert_eq!(key_a, key_b);
    }

    #[test]
    fn test_jpkey_new_distinguishes_attributes() {
        let attr_admin = Attribute::tuple("user.role")
            .single()
            .value("admin")
            .build()
            .unwrap();
        let attr_dev = Attribute::tuple("user.role")
            .single()
            .value("dev")
            .build()
            .unwrap();

        let admin_key = JPKey::new(&[attr_admin]);
        let dev_key = JPKey::new(&[attr_dev]);
        assert_ne!(admin_key, dev_key);
    }

    #[test]
    #[should_panic(expected = "duplicate attribute")]
    fn test_jpkey_new_duplicate_attributes_panic() {
        let attr_admin = Attribute::tuple("user.role")
            .single()
            .value("admin")
            .build()
            .unwrap();
        let attr_dev = Attribute::tuple("user.role")
            .single()
            .value("dev")
            .build()
            .unwrap();

        // Both attributes share the same ZPL key, so JPKey::new should panic.
        let _ = JPKey::new(&[attr_admin, attr_dev]);
    }

    #[test]
    fn test_jp_builder_has_and_add_connect() {
        let mut builder = JPBuilder::default();
        let conditions = vec![
            Attribute::tuple("user.role")
                .single()
                .value("admin")
                .build()
                .unwrap(),
        ];

        assert!(!builder.has(&conditions));
        builder.add_connect(&conditions);
        assert!(builder.has(&conditions));

        let key = JPKey::new(&conditions);
        let jp = builder.policies.get(&key).expect("join policy missing");
        assert_eq!(jp.conditions, conditions);
        assert!(jp.provides.is_none());
        assert_eq!(jp.flags, PFlags::default());
    }

    #[test]
    fn test_jp_builder_add_provides_new_entry() {
        let mut builder = JPBuilder::default();
        let conditions = vec![
            Attribute::tuple("user.region")
                .single()
                .value("emea")
                .build()
                .unwrap(),
        ];

        let service = Service {
            id: "svc1".into(),
            endpoints: vec![Scope {
                protocol: 6,
                flag: None,
                port: Some(443),
                port_range: None,
            }],
            kind: ServiceType::Visa,
        };

        builder.add_provides(&conditions, service, Some(PFlags::vs()));

        let key = JPKey::new(&conditions);
        let jp = builder.policies.get(&key).expect("join policy missing");
        assert_eq!(jp.conditions, conditions);
        assert_eq!(jp.flags, PFlags::vs());
        let provides = jp.provides.as_ref().expect("missing provides");
        assert_eq!(provides.len(), 1);
        assert_eq!(provides[0].id, "svc1");
        assert!(matches!(provides[0].kind, ServiceType::Visa));
        assert_eq!(provides[0].endpoints.len(), 1);
    }

    #[test]
    fn test_jp_builder_add_provides_appends_and_flags() {
        let mut builder = JPBuilder::default();
        let conditions = vec![
            Attribute::tuple("endpoint.env")
                .single()
                .value("prod")
                .build()
                .unwrap(),
        ];

        let service_a = Service {
            id: "svc-a".into(),
            endpoints: vec![Scope {
                protocol: 17,
                flag: None,
                port: Some(53),
                port_range: None,
            }],
            kind: ServiceType::Regular,
        };
        let service_b = Service {
            id: "svc-b".into(),
            endpoints: vec![Scope {
                protocol: 6,
                flag: None,
                port: Some(8443),
                port_range: None,
            }],
            kind: ServiceType::Authentication,
        };

        builder.add_provides(&conditions, service_a, Some(PFlags::vs()));
        builder.add_provides(&conditions, service_b, Some(PFlags::node(false)));

        let key = JPKey::new(&conditions);
        let jp = builder.policies.get(&key).expect("join policy missing");
        let provides = jp.provides.as_ref().expect("missing provides");
        assert_eq!(provides.len(), 2);
        assert_eq!(provides[0].id, "svc-a");
        assert_eq!(provides[1].id, "svc-b");

        let mut expected_flags = PFlags::vs();
        expected_flags.or(PFlags::node(false));
        assert_eq!(jp.flags, expected_flags);
    }
}
