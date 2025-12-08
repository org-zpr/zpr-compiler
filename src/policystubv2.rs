use std::collections::HashMap;

use crate::errors::CompilationError;
use crate::fabric::ServiceType;
use crate::policywriter::{PFlags, PolicyContainer, PolicyWriter, TSType};
use crate::protocols::Protocol;
use crate::ptypes::{Attribute, Signal};

#[derive(Default)]
pub struct PolicyBinaryV2 {}

/// Stub V2 binary policy container.
#[derive(Default)]
pub struct PolicyContainerV2 {}

impl PolicyBinaryV2 {
    pub fn new() -> PolicyBinaryV2 {
        PolicyBinaryV2::default()
    }
}

impl PolicyContainer for PolicyContainerV2 {
    fn contain_policy(
        &self,
        _policy_data: Vec<u8>,
        _signature: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CompilationError> {
        Err(CompilationError::VersionError("v2".to_string()))
    }
}

impl PolicyWriter for PolicyBinaryV2 {
    fn write_created_timestamp(&mut self, _timestamp: &str) {}
    fn write_policy_version(&mut self, _version: u64) {}
    fn write_policy_revision(&mut self, _revision: &str) {}
    fn write_policy_metadata(&mut self, _metadata: &str) {}
    fn write_max_visa_lifetime(&mut self, _lifetime: std::time::Duration) {}
    fn write_attribute_tables(
        &mut self,
        _key_table: &HashMap<String, usize>,
        _value_table: &HashMap<String, usize>,
    ) {
    }
    fn write_connect_match(&mut self, _conditions: &[Attribute]) {}
    fn write_connect_match_for_provider(
        &mut self,
        _svc_attrs: &[Attribute],
        _svc_id: &str,
        _stype: &ServiceType,
        _endpoint: &str,
        _flags: Option<PFlags>,
    ) {
    }
    fn write_service_cert(&mut self, _svc_id: &str, _cert_data: &[u8]) {}
    fn write_bootstrap_key(&mut self, _cn: &str, _keydata: &[u8]) {}
    fn write_cpolicy(
        &mut self,
        _svc_id: &str,
        _policy_num: usize,
        _protocol: &Protocol,
        _allow: bool,
        _cli_conditions: &[Attribute],
        _svc_conditions: &[Attribute],
        _signal: Option<Signal>,
        _pline: &str,
    ) {
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
    }
    fn print_stats(&self) {}

    fn finalize(self) -> Result<Vec<u8>, CompilationError> {
        Err(CompilationError::VersionError("v2".to_string()))
    }
}
