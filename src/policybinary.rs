use std::collections::HashMap;

use ::polio::policy_capnp;
use capnp::message::HeapAllocator;
use polio::polio;

use crate::fabric::ServiceType; // TODO: remove refs to fabric
use crate::ptypes::Attribute;
use crate::zpl;

pub trait PolicyWriter {
    fn write_compiler_version(&mut self, major: u32, minor: u32, patch: u32);
    fn write_created_timestamp(&mut self, timestamp: &str);
    fn write_policy_version(&mut self, version: u64);
    fn write_policy_revision(&mut self, revision: &str);
    fn write_policy_metadata(&mut self, metadata: &str);
    fn write_max_visa_lifetime(&mut self, lifetime: std::time::Duration);
    fn write_connect_match(&mut self, conditions: &[Attribute]);
    fn write_connect_match_for_provider(
        &mut self,
        svc_attrs: &[Attribute],
        svc_id: &str,
        stype: &ServiceType,
        endpoint: &str,
        flags: Option<PFlags>,
    );
    fn write_service_cert(&mut self, svc_id: &str, cert_data: &[u8]);

    // This one is just to support V1 lookup tables.
    fn write_attribute_tables(
        &mut self,
        key_table: &HashMap<String, usize>,
        value_table: &HashMap<String, usize>,
    );
}

/// This value for a PROC in a connect record means NO PROC.  Binary format v1.
pub const NO_PROC: u32 = u32::MAX; // 0xffffffff

/// In V1 These flags are used to set the type of service in the PROC.
/// TODO: Maybe switch to using the protocol buffer type directly?
#[derive(Debug, Clone, PartialEq, Copy)]
pub struct PFlags {
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

#[derive(Default)]
pub struct PolicyBinaryV1 {
    container: polio::PolicyContainer,
    policy: polio::Policy,
    key_table: HashMap<String, usize>,
    value_table: HashMap<String, usize>,
    connects_table: HashMap<String, usize>, // connect hash string -> connect index

    // Before writing service IDs into the policy we clean up the names by converting
    // whitespace into underscores.  This map keeps track of that so that we use the
    // same "mangled" names for fabric service names throughout the policy.
    name_mangler: HashMap<String, String>, // fabric IDs -> policy IDs
}

pub struct PolicyBinaryV2<'a> {
    container: policy_capnp::policy_container::Builder<'a>,

    policy: policy_capnp::policy::Builder<'a>,
}

/// Holds memory for the two capn proto messages.
/// Needs to live as long as the PolicyBinaryV2.
pub struct PbV2Memory {
    container_msg: Box<::capnp::message::Builder<HeapAllocator>>,
    policy_msg: Box<::capnp::message::Builder<HeapAllocator>>,
}

impl PbV2Memory {
    pub fn new() -> PbV2Memory {
        let container_msg = Box::new(::capnp::message::Builder::new_default());
        let policy_msg = Box::new(::capnp::message::Builder::new_default());
        PbV2Memory {
            container_msg,
            policy_msg,
        }
    }
}

impl PolicyBinaryV2<'_> {
    pub fn new<'a>(msg_mem: &'a mut PbV2Memory) -> PolicyBinaryV2<'a> {
        let container = msg_mem
            .container_msg
            .init_root::<policy_capnp::policy_container::Builder>();
        let policy = msg_mem
            .policy_msg
            .init_root::<policy_capnp::policy::Builder>();

        PolicyBinaryV2 { container, policy }
    }
}

impl PolicyWriter for PolicyBinaryV2<'_> {
    fn write_compiler_version(&mut self, major: u32, minor: u32, patch: u32) {
        self.container.set_zplc_ver_major(major);
        self.container.set_zplc_ver_minor(minor);
        self.container.set_zplc_ver_patch(patch);
    }
    fn write_created_timestamp(&mut self, timestamp: &str) {
        self.policy.set_created(timestamp);
    }
    fn write_policy_version(&mut self, version: u64) {
        self.policy.set_version(version);
    }
    fn write_policy_revision(&mut self, _revision: &str) {
        // nop
    }
    fn write_policy_metadata(&mut self, metadata: &str) {
        self.policy.set_metadata(metadata);
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
        // TODO.
    }
    fn write_connect_match_for_provider(
        &mut self,
        svc_attrs: &[Attribute],
        svc_id: &str,
        stype: &ServiceType,
        endpoint: &str,
        flags: Option<PFlags>,
    ) {
        // TODO
    }
    fn write_service_cert(&mut self, _svc_id: &str, _cert_data: &[u8]) {
        // nop
    }
}

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
}

impl PolicyWriter for PolicyBinaryV1 {
    fn write_compiler_version(&mut self, major: u32, minor: u32, patch: u32) {
        self.container.version_major = major;
        self.container.version_minor = minor;
        self.container.version_patch = patch;
    }
    fn write_created_timestamp(&mut self, timestamp: &str) {
        self.container.policy_date = timestamp.to_string();
        self.policy.policy_date = timestamp.to_string();
    }
    fn write_policy_version(&mut self, version: u64) {
        self.container.policy_version = version;
        self.policy.policy_version = version;
    }
    fn write_policy_revision(&mut self, revision: &str) {
        self.container.policy_revision = revision.to_string();
        self.policy.policy_revision = revision.to_string();
    }
    fn write_policy_metadata(&mut self, metadata: &str) {
        self.container.policy_metadata = metadata.to_string();
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
}
