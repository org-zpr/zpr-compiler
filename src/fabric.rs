//! fabric.rs - A ZPR network fabric.  To create one, use [crate::weaver::weave].
//! This datastructre is designed to be easily massaged into the binary format
//! needed by the prototype visa service.

use core::fmt;
use std::collections::HashMap;

use crate::errors::CompilationError;
use crate::protocols::{PortSpec, Protocol};
use crate::ptypes::Signal;
use zpr::policy_types::{Attribute, ServiceType};

/// A service oriented view of the network.
#[derive(Debug, Clone, Default)]
pub struct Fabric {
    pub revision: String,
    pub services: Vec<FabricService>,
    pub nodes: Vec<FabricNode>,
    pub default_auth_cert_asn: Vec<u8>, // CA cert for default/builtin trusted auth
    pub bootstrap_records: HashMap<String, Vec<u8>>, // bootstrap records maps a CN to a der-encoded public key
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FabricService {
    pub config_id: String, // Service name as specified in configuration and ZPL.
    pub fabric_id: String, // Service name assigned in the fabric
    pub protocol: Option<Protocol>, // For an auth service this is the visa-service facing protocol.
    pub provider_attrs: Vec<Attribute>, // Set of provider attributes required to offer the service
    pub client_policies: Vec<ClientPolicy>, // List of consumer policies
    pub service_type: ServiceType,
    pub certificate: Option<Vec<u8>>, // Certificate for this (trusted) service
    pub client_service_name: Option<String>, // For an AUTH service, the name of the optional client service.
    pub returns_attrs: Option<HashMap<String, Attribute>>, // list of attribute keys (with domains) -- only for trusted services
    pub identity_attrs: Option<Vec<String>>, // list of attribute keys (with domains) -- only for trusted services
}

#[derive(Debug, Clone)]
pub struct FabricNode {
    pub node_id: String,
    pub provider_attrs: Vec<Attribute>, // parsed out of config::Node.provider
}

#[derive(Debug, Clone, Default)]
pub struct PLine {
    pub lineno: usize,
    pub zpl: String,
}

impl PLine {
    pub fn new(lineno: usize, zpl: &str) -> PLine {
        PLine {
            lineno,
            zpl: zpl.into(),
        }
    }
    pub fn new_builtin(zpl: &str) -> PLine {
        PLine {
            lineno: 0,
            zpl: zpl.into(),
        }
    }
}

impl fmt::Display for PLine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.lineno == 0 {
            write!(f, "(builtin) {}", self.zpl)
        } else {
            write!(f, "(line {}) {}", self.lineno, self.zpl)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientPolicy {
    /// If true, this policy denies access
    pub never_allow: bool,

    /// If true, this policy is only for access, not for setting up a connection
    pub access_only: bool,

    /// List of attributes that must be met by a client for the policy to apply
    pub cli_condition: Vec<Attribute>,

    /// List of attributes that must be met by a service for the policy to apply
    pub svc_condition: Vec<Attribute>,

    /// Signal containing message and destination
    pub signal: Option<Signal>,

    /// ZPL causing this policy
    pub zpl_line: PLine,
}

fn plural(word: &str, count: usize) -> String {
    if count == 1 {
        word.to_string()
    } else {
        format!("{}s", word)
    }
}

/// Debugging output
impl fmt::Display for Fabric {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "revision: {}", self.revision)?;
        writeln!(
            f,
            "default auth cert: {}bytes",
            self.default_auth_cert_asn.len()
        )?;
        if self.bootstrap_records.is_empty() {
            writeln!(f, "no bootstrap records")?;
        } else {
            let bslen = self.bootstrap_records.len();
            writeln!(f, "{} bootstrap {}:", bslen, plural("record", bslen))?;
            for cn in self.bootstrap_records.keys() {
                writeln!(f, "  - {}", cn)?;
            }
        }
        writeln!(
            f,
            "{} {} - {} {}",
            self.services.len(),
            plural("service", self.services.len()),
            self.nodes.len(),
            plural("node", self.nodes.len())
        )?;
        for s in &self.services {
            writeln!(f, "  service: {}  (type={:?})", s.fabric_id, s.service_type)?;
            match s.service_type {
                ServiceType::Trusted(ref api) => {
                    writeln!(f, "    API: {}", api)?;
                    writeln!(f, "    client-service: {:?}", s.client_service_name)?;
                }
                _ => {}
            }
            match s.protocol {
                Some(ref p) => writeln!(f, "    protocol: {:?}", p)?,
                None => writeln!(f, "    protocol: (none)")?,
            }
            writeln!(f, "    provider attrs:")?;
            for a in &s.provider_attrs {
                writeln!(f, "      {}", a.to_instance_string())?;
            }
            writeln!(f, "    policies:")?;
            if s.client_policies.is_empty() {
                writeln!(f, "      (none)")?;
            }
            for (i, cp) in s.client_policies.iter().enumerate() {
                if cp.cli_condition.is_empty() {
                    writeln!(f, "      {}.client)  (NONE)", i + 1)?;
                } else {
                    writeln!(
                        f,
                        "      {}.client)  {}",
                        i + 1,
                        cp.cli_condition
                            .iter()
                            .map(|a| a.to_instance_string())
                            .collect::<Vec<String>>()
                            .join(", ")
                    )?;
                }
                if cp.svc_condition.is_empty() {
                    writeln!(f, "      {}.service)  (NONE)", i + 1)?;
                } else {
                    writeln!(
                        f,
                        "      {}.service)  {}",
                        i + 1,
                        cp.svc_condition
                            .iter()
                            .map(|a| a.to_instance_string())
                            .collect::<Vec<String>>()
                            .join(", ")
                    )?;
                }
                if cp.signal.is_some() {
                    writeln!(f, "      {}.signal) {}", i + 1, cp.signal.as_ref().unwrap())?;
                }
            }
        }
        for n in &self.nodes {
            writeln!(f, "  node: {}", n.node_id)?;
            writeln!(f, "    provider attrs:")?;
            for a in &n.provider_attrs {
                writeln!(f, "      {}", a.to_instance_string())?;
            }
        }
        writeln!(f)
    }
}

impl Fabric {
    /// You must add client services associated with the trusted service before adding a trusted service.
    pub fn add_trusted_service(
        &mut self,
        id: &str,
        protocol: &Protocol,
        api: &str,
        provider_attrs: &[Attribute],
        certificate: Option<Vec<u8>>,
        client_service_name: &str,
        returns_attrs: Option<HashMap<String, Attribute>>,
        identity_attrs: Option<Vec<String>>,
    ) -> Result<(), CompilationError> {
        for s in &self.services {
            if s.config_id == id {
                return Err(CompilationError::BuildError(format!(
                    "cannot add duplicate trusted service: already exists: {id}"
                )));
            }
        }

        println!("XXX fabric::add_trusted_service {id}");

        let fs = FabricService {
            config_id: id.to_string(),
            fabric_id: id.to_string(),
            protocol: Some(protocol.clone()),
            provider_attrs: provider_attrs.to_vec(),
            client_policies: Vec::new(),
            service_type: ServiceType::Trusted(api.to_string()),
            certificate,
            client_service_name: Some(client_service_name.to_string()),
            returns_attrs: returns_attrs,
            identity_attrs: identity_attrs,
        };
        self.services.push(fs);
        Ok(())
    }

    /// Add the service and the attributes that are required to provide it.
    /// There may be many services with the same `id`, but they must then have
    /// different attribute lists.
    ///
    /// Returns the fabric ID assigned to the service.
    pub fn add_service(
        &mut self,
        id: &str,
        protocol: &Protocol,
        attrs: &[Attribute],
        stype: ServiceType,
    ) -> Result<String, CompilationError> {
        assert!(stype != ServiceType::Undefined); // programming error
        match &stype {
            ServiceType::BuiltIn => {
                return Err(CompilationError::BuildError(format!(
                    "illegal add of a BUILTIN service: {}",
                    id
                )));
            }
            ServiceType::Trusted(_) => {
                return Err(CompilationError::BuildError(format!(
                    "add_service cannot add a TRUSTED service -- use add_trusted_service('{}')",
                    id
                )));
            }
            _ => {}
        }
        if stype == ServiceType::Regular && id.starts_with("/zpr") {
            return Err(CompilationError::ConfigError(format!(
                "service {} cannot start with reserved prefix '/zpr'",
                id
            )));
        }
        let mut svc_instance = 0;
        for s in &self.services {
            if s.config_id == id {
                if s.matches_attributes(attrs) {
                    // Sanity check:
                    if s.service_type != stype {
                        return Err(CompilationError::ConfigError(format!(
                            "service {} has conflicting types: {:?} and {:?}",
                            id, s.service_type, stype
                        )));
                    }
                    return Ok(s.fabric_id.clone()); // already have this service
                }
                svc_instance += 1;
            }
        }
        let fabric_id = self.fabric_id_from_config_id_and_count(id, svc_instance);
        println!(
            "XXX fabric::add_service {fabric_id} with provider attrs: {:?}",
            attrs
        );
        let fs = FabricService {
            config_id: id.to_string(),
            fabric_id: fabric_id.clone(),
            protocol: Some(protocol.clone()),
            provider_attrs: attrs.to_vec(),
            client_policies: Vec::new(),
            service_type: stype,
            certificate: None,
            client_service_name: None,
            returns_attrs: None,
            identity_attrs: None,
        };
        self.services.push(fs);
        Ok(fabric_id)
    }

    /// Create a fabric_id from a config_id.
    fn fabric_id_from_config_id_and_count(&self, config_id: &str, count: usize) -> String {
        if count > 0 {
            format!("{}#{}", config_id, count)
        } else {
            config_id.to_string()
        }
    }

    pub fn add_builtin_service(
        &mut self,
        id: &str,
        protocol: &Protocol,
        attrs: &[Attribute],
    ) -> Result<String, CompilationError> {
        let mut svc_instance = 0;
        for s in &self.services {
            if s.config_id == id {
                if s.matches_attributes(attrs) {
                    // Sanity check:
                    if s.service_type != ServiceType::BuiltIn {
                        return Err(CompilationError::ConfigError(format!(
                            "service {} has conflicting types: {:?} and BuiltIn",
                            id, s.service_type
                        )));
                    }
                    return Ok(s.fabric_id.clone()); // already have this service
                }
                svc_instance += 1;
            }
        }
        let fabric_id = self.fabric_id_from_config_id_and_count(id, svc_instance);
        println!("XXX fabric::add_buildin_service: {fabric_id}");
        let fs = FabricService {
            config_id: id.to_string(),
            fabric_id: fabric_id.clone(),
            protocol: Some(protocol.clone()),
            provider_attrs: attrs.to_vec(),
            client_policies: Vec::new(),
            service_type: ServiceType::BuiltIn,
            certificate: None,
            client_service_name: None,
            returns_attrs: None,
            identity_attrs: None,
        };
        self.services.push(fs);
        Ok(fabric_id)
    }

    pub fn get_visa_service(&self) -> Option<&FabricService> {
        self.services
            .iter()
            .find(|s| s.service_type == ServiceType::Visa)
    }

    /// Return TRUE if the service with given fabric_id is in our fabric.
    pub fn has_service(&self, fabric_id: &str) -> bool {
        self.services.iter().any(|s| s.fabric_id == fabric_id)
    }

    /// Get a reference to one of the services.
    pub fn get_service(&self, fabric_id: &str) -> Option<&FabricService> {
        self.services.iter().find(|s| s.fabric_id == fabric_id)
    }

    /// Add a node to the fabric
    pub fn push_node(&mut self, node: FabricNode) {
        self.nodes.push(node);
    }

    /// Add a condition (aka policy aka rule) to an existing service specified by the
    /// fabric service ID.  This adds client conditions.
    pub fn add_condition_to_service(
        &mut self,
        never_allow: bool,
        service_id: &str,
        cli_attrs: &[Attribute],
        svc_attrs: &[Attribute],
        access_only: bool,
        signal: Option<Signal>,
        pline: &PLine,
    ) -> Result<(), CompilationError> {
        let svc = self.services.iter_mut().find(|s| s.fabric_id == service_id);
        if svc.is_none() {
            // programming error
            return Err(CompilationError::BuildError(format!(
                "add_condition_to_service: service not found: {}",
                service_id
            )));
        }
        let svc = svc.unwrap();

        // For the service attributes, only add a policy if the attributes are not
        // already present in the provider attributes.
        let unique_svc_attrs: Vec<Attribute> = svc_attrs
            .iter()
            .filter(|a| !svc.provider_attrs.contains(a))
            .cloned()
            .collect();

        // TODO check that service signal wants to signal to exists?

        svc.client_policies.push(ClientPolicy {
            never_allow: never_allow,
            cli_condition: cli_attrs.to_vec(),
            svc_condition: unique_svc_attrs.to_vec(),
            access_only,
            signal,
            zpl_line: pline.clone(),
        });
        Ok(())
    }
}

impl FabricService {
    /// True if this services attributes overlap with `other_attrs` exactly.
    pub fn matches_attributes(&self, other_attrs: &[Attribute]) -> bool {
        if other_attrs.len() != self.provider_attrs.len() {
            return false;
        }
        for oa in other_attrs {
            if !self.provider_attrs.contains(oa) {
                return false;
            }
        }
        true
    }

    /// Expect that this service has a L7 protocol name and
    /// a single port.  If that is true, return (L7 protocol name, port)
    /// else return error.
    pub fn get_l7protocol_and_port(&self) -> Result<(String, u16), CompilationError> {
        let p = self.protocol.as_ref().ok_or_else(|| {
            CompilationError::ConfigError(format!(
                "Service {} does not have a protocol",
                self.fabric_id
            ))
        })?;
        if !p.has_port() {
            return Err(CompilationError::ConfigError(format!(
                "Service {} does not have a port",
                self.fabric_id
            )));
        }
        let l7name = p.get_layer7().ok_or_else(|| {
            CompilationError::ConfigError(format!(
                "Service {} does not have a layer 7 protocol",
                self.fabric_id
            ))
        })?;
        let pslist = p.get_port().unwrap();
        if pslist.len() != 1 {
            return Err(CompilationError::ConfigError(format!(
                "Service {} does not have a single port",
                self.fabric_id
            )));
        }
        match pslist[0] {
            PortSpec::Single(pnum) => Ok((l7name.to_string(), pnum)),
            _ => Err(CompilationError::ConfigError(format!(
                "Service {} does not have a single port",
                self.fabric_id
            ))),
        }
    }
}
