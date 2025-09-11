use ::polio::policy_capnp;
use capnp::message::HeapAllocator;
use std::collections::HashMap;

use crate::errors::CompilationError;
use crate::fabric::ServiceType; // TODO: remove refs to fabric
use crate::policywriter::{PFlags, PolicyWriter, TSType};
use crate::protocols::Protocol;
use crate::ptypes::Attribute; // TODO: remove refs to fabric

pub struct PolicyBinaryV2<'a> {
    policy: policy_capnp::policy::Builder<'a>,
}

/// Holds memory for the two capn proto messages.
/// Needs to live as long as the PolicyBinaryV2.
pub struct PbV2Memory {
    policy_msg: Box<::capnp::message::Builder<HeapAllocator>>,
}

impl PbV2Memory {
    pub fn new() -> PbV2Memory {
        let policy_msg = Box::new(::capnp::message::Builder::new_default());
        PbV2Memory { policy_msg }
    }
}

impl PolicyBinaryV2<'_> {
    pub fn new<'a>(msg_mem: &'a mut PbV2Memory) -> PolicyBinaryV2<'a> {
        let policy = msg_mem
            .policy_msg
            .init_root::<policy_capnp::policy::Builder>();

        PolicyBinaryV2 { policy }
    }
}

impl PolicyWriter for PolicyBinaryV2<'_> {
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
    fn write_connect_match(&mut self, _conditions: &[Attribute]) {
        // TODO.
    }
    fn write_connect_match_for_provider(
        &mut self,
        _svc_attrs: &[Attribute],
        _svc_id: &str,
        _stype: &ServiceType,
        _endpoint: &str,
        _flags: Option<PFlags>,
    ) {
        // TODO
    }
    fn write_service_cert(&mut self, _svc_id: &str, _cert_data: &[u8]) {
        // nop
    }
    fn write_bootstrap_key(&mut self, _cn: &str, _keydata: &[u8]) {
        // nop
    }
    fn write_cpolicy(
        &mut self,
        _svc_id: &str,
        _policy_num: usize,
        _protocol: &Protocol,
        _allow: bool,
        _cli_conditions: &[Attribute],
        _svc_conditions: &[Attribute],
    ) {
        // TODO
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
        // TODO?
    }
    fn finalize(&mut self) -> Result<Vec<u8>, CompilationError> {
        // TODO.
        return Ok(Vec::new());
    }
}
