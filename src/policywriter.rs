use std::collections::HashMap;

use crate::errors::CompilationError;
use crate::protocols::Protocol;
use crate::ptypes::Signal;
use zpr::policy_types::{Attribute, PFlags, ServiceType};

pub enum TSType {
    VsAuth,    // trusted service <-> visa service
    ActorAuth, // trusted service <-> adapter
}

pub trait PolicyWriter {
    fn print_stats(&self);

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
        //endpoint: &str,
        endpoint: &Protocol,
        flags: Option<PFlags>,
    );

    fn write_service_cert(&mut self, svc_id: &str, cert_data: &[u8]);
    fn write_bootstrap_key(&mut self, cn: &str, keydata: &[u8]);

    /// Write a Communication Policy (allow or deny)
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
    );

    // This one is just to support V1 lookup tables.
    fn write_attribute_tables(
        &mut self,
        key_table: &HashMap<String, usize>,
        value_table: &HashMap<String, usize>,
    );

    fn write_trusted_service(
        &mut self,
        svc_id: &str,
        ts_type: TSType,
        query_uri: Option<&str>,
        validate_uri: Option<&str>,
        returns_attrs: Option<&HashMap<String, Attribute>>,
        identity_attrs: Option<&Vec<String>>,
    );

    fn finalize(self) -> Result<Vec<u8>, CompilationError>;
}

pub trait PolicyContainer {
    fn contain_policy(
        &self,
        policy_data: Vec<u8>,
        signature: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CompilationError>;
}
