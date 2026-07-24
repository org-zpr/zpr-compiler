//! policybuilder.rs - Build a protocol buffer policy from the fabric.

use chrono::prelude::*;
use std::collections::HashMap;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::context::CompilationCtx;
use crate::errors::CompilationError;
use crate::fabric::Fabric;
use crate::policywriter::PolicyWriter;
use crate::protocols::{PortSpec, Protocol};
use crate::zpl;
use zpr::policy_types::{Attribute, PFlags, ServiceType};

#[allow(dead_code)]
#[derive(Default)]
pub struct PolicyBuilder<T: PolicyWriter> {
    verbose: bool,
    policy_date: String,
    //xpolicy: polio::Policy,
    policy_writer: T,
    connects_table: HashMap<String, usize>, // connect hash string -> connect index

    // Before writing service IDs into the policy we clean up the names by converting
    // whitespace into underscores.  This map keeps track of that so that we use the
    // same "mangled" names for fabric service names throughout the policy.
    name_mangler: HashMap<String, String>, // fabric IDs -> policy IDs
}

/// That which can create a policy, requires a [Fabric] to do so.
impl<T: PolicyWriter> PolicyBuilder<T> {
    /// Create the builder. This sets some topical info in the policy.
    ///
    /// Once created, you should call [PolicyBuilder::with_max_visa_lifetime], then
    /// [PolicyBuilder::with_fabric] (which does the real work), and finally
    /// [PolicyBuilder::build] to get the compiled policy.
    pub fn new(verbose: bool, mut policy_writer: T) -> PolicyBuilder<T> {
        let utc: DateTime<Utc> = Utc::now();
        let policy_date = utc.to_rfc3339_opts(SecondsFormat::Secs, true);
        let tsnow = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let policy_version = tsnow.as_secs();

        let md = metadata(&policy_date);

        policy_writer.write_created_timestamp(&policy_date);
        policy_writer.write_policy_version(policy_version);
        policy_writer.write_policy_metadata(&md);

        if verbose {
            println!("creating binary policy");
            println!("metadata: {}", md);
        }

        PolicyBuilder {
            verbose,
            policy_date,
            policy_writer,
            connects_table: HashMap::new(),
            name_mangler: HashMap::new(),
        }
    }

    /// Returns the built policy. This doesn't actually do anything except return the already built policy.
    /// you must call [PolicyBuilder::with_fabric] to do the real work before calling this.
    pub fn build(self) -> Result<Vec<u8>, CompilationError> {
        self.policy_writer.finalize()
    }

    /// The binary policy has a place for global settings, the only valid
    /// one in the prototype is "max visa lifetime".  Set that here.
    pub fn with_max_visa_lifetime(&mut self, lifetime: Duration) {
        self.policy_writer.write_max_visa_lifetime(lifetime);
    }

    /// From the Fabric we get a bunch of details for the policy.
    ///
    ///   - The set of connects, which describe what agents can connect to the network.
    ///   - The "procs" which are little programs that run when an agent connects.
    ///   - The attribute keys and values lookup tables.
    ///   - The set of communication policies which set which agents can access which services.
    ///   - The links which are empty for now as only a single node is supported (TODO).
    ///   - The services which is only used for AUTH services.
    ///   - The certificates used for trusted services and for the default/internal auth service.
    ///
    /// This does most of the work in building the policy.
    pub fn with_fabric(
        &mut self,
        fabric: &Fabric,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        self.policy_writer
            .write_policy_revision(&fabric.get_revision());

        // V1 policy puts all the attribute keys and values used by the
        // policy into a lookup table and then refers to them by index
        // in its communication policies.  This was to save sapce.  V2
        // does not do this.
        let mut key_table = HashMap::new(); // key -> index
        let mut value_table = HashMap::new(); // value -> index
        self.populate_key_table(fabric, &mut key_table);
        self.populate_value_table(fabric, &mut value_table);
        self.policy_writer
            .write_attribute_tables(&key_table, &value_table);

        self.set_connects(fabric)?;
        self.set_policies(fabric)?;
        self.set_topology(fabric)?;
        self.set_default_auth(fabric, ctx)?;
        self.set_bootstrap(fabric, ctx)?;
        self.set_trusted_service_records(fabric, ctx)?;

        if self.verbose {
            self.policy_writer.print_stats();
        }
        Ok(())
    }

    /// Configure the default (internal) authentication service in the policy. This is
    /// essentially just storing a CA certificate along with the expected prefix.
    fn set_default_auth(
        &mut self,
        fabric: &Fabric,
        _ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        if let Some(cert_data) = fabric.get_default_auth_cert() {
            self.policy_writer
                .write_service_cert(&zpl::DEFAULT_TS_PREFIX, cert_data);
        }
        Ok(())
    }

    /// Emit one shared `TrustedService` metadata record per woven `file` or
    /// `validation/2` service. There is no record for the builtin `default`
    /// service (it is not a fabric `Trusted` service) nor for the validation/2
    /// adapter-facing authentication service (it is tied to its vs-facing
    /// `validation/2` service which does get a record). Validation/2 network
    /// join/communication policies are also emitted through the normal fabric
    /// paths (`set_connects`/`set_policies`).
    fn set_trusted_service_records(
        &mut self,
        fabric: &Fabric,
        _ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        for svc in &fabric.services {
            match svc.service_type {
                ServiceType::Trusted(_) => {}
                _ => continue, // not a trusted service
            }

            let record = svc.trusted_service.as_ref().ok_or_else(|| {
                CompilationError::BuildError(format!(
                    "trusted service {} is missing its metadata record",
                    svc.fabric_id
                ))
            })?;

            // Trusted-service IDs are restricted, so the fabric id is used unchanged for both the
            // join-policy `Service.id` and `TrustedService.service_id`; they must be identical.
            if svc.fabric_id != record.service_id {
                return Err(CompilationError::BuildError(format!(
                    "trusted service fabric id '{}' does not match record service_id '{}'",
                    svc.fabric_id, record.service_id
                )));
            }

            self.policy_writer
                .write_trusted_service_record(record.clone());
        }
        Ok(())
    }

    fn set_bootstrap(
        &mut self,
        fabric: &Fabric,
        _ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        for (cnval, keydata) in fabric.get_bootstrap_records() {
            self.policy_writer.write_bootstrap_key(&cnval, keydata);
        }
        Ok(())
    }

    // Each policy (called a CPolicy for "Communication Policy" in the protobuf)
    // lists a service, a scope (which is a protocol/port) and a collection
    // of attributes.  For a policy to be satisfied at the visa service ALL
    // the condititions must be met by the CLIENT.
    //
    // Conditions that must be met by the service are stored in the `svc_conditions`
    // field. Note that some service conditions are applied in a connect policy.
    // Eg, an actor is not permitted to advertise a service unless it has some specific
    // conditions.
    //
    // As an aside, i'm not exactly sure why the protobuf format has a list of
    // lists of conditions rather than just a list.
    fn set_policies(&mut self, fabric: &Fabric) -> Result<(), CompilationError> {
        // Each service has a set of client policies.
        // Each policy is a list of conditions that permit access to the service.
        // We convert each policy to its own CPolicy.
        for svc in &fabric.services {
            let svc_id = self.get_canonical_service_name(&svc.fabric_id);
            for (i, policy) in svc.client_policies.iter().enumerate() {
                let protocol = svc.protocol.clone().unwrap(); // MUST BE SET
                self.policy_writer.write_cpolicy(
                    &svc_id,
                    i + 1,
                    &protocol,
                    !policy.never_allow,
                    &policy.cli_condition,
                    &policy.svc_condition,
                    policy.signal.clone(),
                    &policy.zpl_line.to_string(),
                );
            }
        }
        Ok(())
    }

    fn set_topology(&mut self, fabric: &Fabric) -> Result<(), CompilationError> {
        for link in &fabric.links {
            self.policy_writer.write_link(
                &link.link_id,
                &link.node_a.zpr_addr,
                &link.node_a.substrate.host,
                link.node_a.substrate.port,
                &link.node_b.zpr_addr,
                &link.node_b.substrate.host,
                link.node_b.substrate.port,
                &link.link_attrs,
            );
        }
        Ok(())
    }

    fn set_connects(&mut self, fabric: &Fabric) -> Result<(), CompilationError> {
        for svc in &fabric.services {
            // Add join policies for agents that provide a service
            match svc.service_type {
                ServiceType::Regular
                | ServiceType::Visa
                | ServiceType::BuiltIn
                | ServiceType::Authentication => {
                    let flags = if svc.service_type == ServiceType::Visa {
                        Some(PFlags::vs())
                    } else {
                        None
                    };
                    let svc_id = self.get_canonical_service_name(&svc.fabric_id);
                    self.policy_writer.write_connect_match_for_provider(
                        &svc.provider_attrs,
                        &svc_id,
                        &svc.service_type,
                        Some(svc.protocol.as_ref().expect("service must have a protocol")),
                        flags,
                    )
                }

                ServiceType::Trusted(ref api) => {
                    // Only a `file` trusted service may have no protocol; all network-facing
                    // services must carry one.
                    if svc.protocol.is_none() && api != zpl::TS_API_FILE {
                        return Err(CompilationError::BuildError(format!(
                            "trusted service {} of type '{}' is missing a protocol",
                            svc.fabric_id, api
                        )));
                    }
                    self.policy_writer.write_connect_match_for_provider(
                        &svc.provider_attrs,
                        &svc.fabric_id,
                        &svc.service_type,
                        svc.protocol.as_ref(),
                        None,
                    );
                    if let Some(cert_data) = &svc.certificate {
                        self.policy_writer
                            .write_service_cert(&svc.fabric_id, cert_data);
                    };
                }
                ServiceType::Undefined => {
                    panic!("undefined service type in fabric{}", svc.config_id);
                }
            }
        }
        // Any agent that provides a node can connect
        for node in &fabric.nodes {
            // The visa service needs the node to register as a service, but the
            // only service on a node is really the visa support service, but we
            // create that as a separate service elsewhere.
            //
            // So this registers as node service but uses a bogus endpoint.
            let svc_id = format!("/zpr/{}", &node.node_id);

            let dummy_prot = Protocol::tcp("dummy")
                .add_port(PortSpec::Single(1))
                .build()
                .unwrap();

            self.policy_writer.write_connect_match_for_provider(
                &node.provider_attrs,
                &svc_id,
                &ServiceType::Regular,
                Some(&dummy_prot),
                Some(PFlags::node(true)), // TODO: Not all nodes are VS docks
            );
        }
        Ok(())
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

    // Helper function that can create our lookup table that maps
    // keys or attributes to indexes.
    //
    // See [PolicyBuilder::populate_key_table] and [PolicyBuilder::populate_value_table].
    fn populate_lookup_table(
        &self,
        fabric: &Fabric,
        table: &mut HashMap<String, usize>,
        extraction_f: fn(&Attribute) -> String,
    ) {
        for s in &fabric.services {
            for a in &s.provider_attrs {
                let key = extraction_f(a);
                if !table.contains_key(&key) {
                    table.insert(key, table.len());
                }
            }
            for policy in &s.client_policies {
                for attr_vec in [&policy.cli_condition, &policy.svc_condition] {
                    for a in attr_vec {
                        let key = extraction_f(a);
                        if !table.contains_key(&key) {
                            table.insert(key, table.len());
                        }
                    }
                }
            }
        }
        for n in &fabric.nodes {
            for a in &n.provider_attrs {
                let key = extraction_f(a);
                if !table.contains_key(&key) {
                    table.insert(key, table.len());
                }
            }
        }
    }

    /// Create a table of all unique attribute keys.
    fn populate_key_table(&self, fabric: &Fabric, table: &mut HashMap<String, usize>) {
        self.populate_lookup_table(fabric, table, |a| a.zpl_key());
    }

    /// Create a table of all unique attribute values.
    fn populate_value_table(&self, fabric: &Fabric, table: &mut HashMap<String, usize>) {
        self.populate_lookup_table(fabric, table, |a| a.zpl_value());
    }
}

/// Generate some generic metadata.
fn metadata(pdate: &str) -> String {
    let username = env::var("USER").unwrap_or_else(|_| "(anonymous)".to_string());
    format!(
        "compiled {} on {} by {}",
        pdate,
        platform::gethostname(),
        username
    )
}

mod platform {

    #[cfg(target_family = "unix")]
    use nix::unistd;

    #[cfg(target_family = "unix")]
    pub fn gethostname() -> String {
        match unistd::gethostname() {
            Ok(h) => h.to_string_lossy().to_string(),
            Err(_) => "(unknown)".to_string(),
        }
    }

    #[cfg(not(target_family = "unix"))]
    pub fn gethostname() -> String {
        return "(unknown)".to_string();
    }
}
