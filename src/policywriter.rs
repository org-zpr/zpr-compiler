use std::collections::HashMap;

use crate::errors::CompilationError;
use crate::fabric::ServiceType;
use crate::protocols::Protocol;
use crate::ptypes::{Attribute, Signal}; // TODO: remove refs to fabric

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
        endpoint: &str,
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
        returns_attrs: Option<&Vec<String>>,
        identity_attrs: Option<&Vec<String>>,
    );

    fn finalize(&mut self) -> Result<Vec<u8>, CompilationError>;
}

pub trait PolicyContainer {
    fn contain_policy(
        &self,
        policy_data: Vec<u8>,
        signature: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CompilationError>;
}
