use std::collections::HashMap;
use std::net::IpAddr;

use crate::errors::CompilationError;
use crate::protocols::Protocol;
use crate::ptypes::Signal;
use zpr::policy_types::{Attribute, PFlags, ServiceType, TrustedService};

/// To support multiple policy output formats, this trait defines the interface for writing policies.
pub trait PolicyWriter {
    fn print_stats(&self);

    fn write_created_timestamp(&mut self, timestamp: &str);
    fn write_policy_version(&mut self, version: u64);
    fn write_policy_revision(&mut self, revision: &str);
    fn write_policy_metadata(&mut self, metadata: &str);
    fn write_max_visa_lifetime(&mut self, lifetime: std::time::Duration);

    /// Write a join policy for a service provider. `endpoint` is `None` for services with no
    /// network endpoints (a `file` trusted service) which yields an empty endpoint list.
    fn write_connect_match_for_provider(
        &mut self,
        svc_attrs: &[Attribute],
        svc_id: &str,
        stype: &ServiceType,
        endpoint: Option<&Protocol>,
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

    /// Emit one shared `TrustedService` metadata record into the policy's `trustedServices` list.
    fn write_trusted_service_record(&mut self, ts: TrustedService);

    fn write_link(
        &mut self,
        link_id: &str,
        node_a_zpr_addr: &IpAddr,
        node_a_substrate_host: &str,
        node_a_substrate_port: u16,
        node_b_zpr_addr: &IpAddr,
        node_b_substrate_host: &str,
        node_b_substrate_port: u16,
        link_attrs: &[Attribute],
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
