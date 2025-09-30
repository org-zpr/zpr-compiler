//! weaver.rs - Poetically named module that can "weave" a "fabric" from a ZPL policy and configuration.

use base64::prelude::*;
use std::collections::{HashMap, HashSet};

use crate::compilation::Compilation;
use crate::config_api::{ConfigApi, ConfigItem};
use crate::context::CompilationCtx;
use crate::crypto::{digest_as_hex, sha256_of_bytes};
use crate::errors::CompilationError;
use crate::fabric::{Fabric, PLine, ServiceType};
use crate::fabric_util::{squash_attributes, vec_to_attributes};
use crate::protocols::{IanaProtocol, Protocol, ZPR_OAUTH_RSA, ZPR_VALIDATION_2};
use crate::ptypes::{AllowClause, Attribute, Class, ClassFlavor, FPos, Policy};
use crate::zpl;

pub struct Weaver {
    fabric: Fabric,

    // Map the allow clause ID to the fabric service ID.
    allowid_to_fab_svc: HashMap<usize, String>,

    // Track the IDs of the in-use trusted services.
    used_trusted_services: HashSet<String>,
}

/// Weave produces the fabric from the ZPL and Configuration data structures,
pub fn weave(
    comp: &Compilation,
    config: &ConfigApi,
    policy: &Policy,
    ctx: &CompilationCtx,
) -> Result<Fabric, CompilationError> {
    let mut weaver = Weaver::new();

    let pdig = policy
        .digest
        .expect("policy digest must be set prior to calling weave");

    // Use config verison as its digest. Version is hex encoded hash.
    let cdig = match config.must_get("zpr/version") {
        ConfigItem::StrVal(ver) => {
            let mut d = [0u8; 32];
            hex::decode_to_slice(ver, &mut d).expect("version must be a 32 byte hex string");
            d
        }
        _ => {
            return Err(CompilationError::ConfigError(
                "no version in configuration".to_string(),
            ));
        }
    };

    weaver.compute_revision(pdig.as_ref(), &cdig)?;

    // Create a class index which maps class name -> class struct.
    let defaults = Class::defaults();
    let mut class_idx = HashMap::new();
    // Add default classes:
    for defclass in &defaults {
        class_idx.insert(defclass.name.clone(), defclass);
    }
    for cl in &policy.defines {
        class_idx.insert(cl.name.clone(), cl);
    }

    weaver.init_services(comp, &class_idx, policy, config, ctx)?;
    weaver.init_nodes(config)?;
    weaver.add_client_deny_policies(comp, &class_idx, policy, config)?;
    weaver.add_client_allow_policies(comp, &class_idx, policy, config)?;
    // By the time we get here, we have resolved all attributes and so know which trusted
    // services are in play.
    weaver.add_trusted_services(config, ctx)?;
    weaver.add_default_auth(config, ctx)?;
    weaver.add_bootstrap_records(config, ctx)?;

    Ok(weaver.fabric)
}

impl Weaver {
    fn new() -> Self {
        Self {
            fabric: Fabric::default(),
            allowid_to_fab_svc: HashMap::new(),
            used_trusted_services: HashSet::new(),
        }
    }

    fn compute_revision(
        &mut self,
        policy_digest: &[u8],
        config_digest: &[u8],
    ) -> Result<(), CompilationError> {
        let mut revhash = Vec::new();
        revhash.extend_from_slice(policy_digest);
        revhash.extend_from_slice(config_digest);
        let policy_revision_dig = sha256_of_bytes(&revhash);
        self.fabric.revision = digest_as_hex(&policy_revision_dig);
        Ok(())
    }

    /// Figure out the set of services in the fabric.  There may be a bunch of services in
    /// the configuration but we only want the ones that are refefenced in the ZPL.
    fn init_services(
        &mut self,
        comp: &Compilation,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        self.defines_to_services(class_idx, policy, config)?;
        self.allow_clauses_to_services(class_idx, policy, config)?;
        self.visa_services_to_services(comp, class_idx, policy, config, ctx)?;

        Ok(())
    }

    /// Set up the visa service(s) in the fabric.
    /// Most visa service related functionality is built in. However user can set
    /// the attributes of the administrator who is able to access the visa service
    /// admin HTTPS API.
    fn visa_services_to_services(
        &mut self,
        comp: &Compilation,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        let vs_protocol = Protocol::new_l4_with_port(
            "zpr-vs".to_string(),
            IanaProtocol::TCP,
            zpl::VISA_SERVICE_PORT.to_string(),
        );

        // The provider of the visa service is a hardcoded CN value.
        let vs_attrs = vec![Attribute::must_new_single_valued(
            zpl::KATTR_CN,
            zpl::VISA_SERVICE_CN,
        )];
        let fab_svc_id = self.fabric.add_service(
            zpl::VS_SERVICE_NAME,
            &vs_protocol,
            &vs_attrs,
            ServiceType::Visa,
        )?;

        // Visa service has policy that allows nodes to access it.  We use a node role attribute so
        // we don't care about individual node names.
        let pline = PLine::new_builtin("allow node access to visa service");
        let vs_access_attrs = vec![Attribute::must_zpr_internal_attr(zpl::KATTR_ROLE, "node")];
        self.fabric.add_condition_to_service(
            false,
            &fab_svc_id,
            &vs_access_attrs,
            &[],
            true,
            None,
            &pline,
        )?;

        // Now add a service for the admin HTTPS API.
        let admin_api_protocol = Protocol::new_l4_with_port(
            "zpr-vsadmin".to_string(),
            IanaProtocol::TCP,
            zpl::VISA_SERVICE_ADMIN_PORT.to_string(),
        );

        // This AMIN service is provided by the visa service too.
        let fab_admin_svc_id = self.fabric.add_builtin_service(
            &format!("{}/admin", zpl::VS_SERVICE_NAME),
            &admin_api_protocol,
            &vs_attrs,
        )?;

        // The admin permissions come from ZPL allow statements, not from configuration.
        let mut condition_count = 0;
        for (plcy_idx, ac) in policy.allows.iter().enumerate() {
            // Seeking a RHS service class that is the visa service.

            let vs_rhs_count = ac
                .server
                .iter()
                .filter(|c| {
                    c.flavor == ClassFlavor::Service && c.class == zpl::DEF_CLASS_VISA_SERVICE_NAME
                })
                .count();
            if vs_rhs_count < 1 {
                continue;
            }

            // TODO: User may be able to shoot themselves in the foot here if they add
            // too many attributes to VisaService. May want to consider disallowing
            // any attributes on the service (but allow on user and endpoint).

            // The admin access attributes are all the attributes declared on the client side of
            // the clause.
            //
            // TODO: Where do we add the service side attributes for visa service?
            let mut admin_access_attrs = Vec::new();

            for lhs_clause in &ac.client {
                // Add the attributes from this clause
                admin_access_attrs.extend_from_slice(&lhs_clause.with);

                // And add the attributes defined at class level
                admin_access_attrs
                    .extend_from_slice(&attrs_for_class(class_idx, &lhs_clause.class));
            }

            let fp = FPos::from(&ac.server[0].class_tok);
            let attr_map = squash_attributes(&admin_access_attrs, &fp)?;
            let resolved_attrs = self.resolve_attributes(
                attr_map
                    .into_values()
                    .collect::<Vec<Attribute>>()
                    .as_slice(),
                config,
            )?;
            let pline = PLine::new(ac.span.0.line, &comp.zpl_for_allow_statement(plcy_idx));
            if !resolved_attrs.is_empty() {
                self.fabric.add_condition_to_service(
                    false,
                    &fab_admin_svc_id,
                    &resolved_attrs,
                    &[], // TODO: Should we consider RHS attributes?
                    false,
                    None,
                    &pline,
                )?;
                condition_count += 1;
            }
        }
        if condition_count == 0 {
            // TODO: is this an error?
            ctx.warn("no policy granting VisaService admin access")?;
        }

        // TODO: When we get around to trusted services, we need to add builtin rules
        //       that grant VS access to the trusted services.
        //       And adapters also have rules (to access the OAuth endpoints).
        Ok(())
    }

    /// Make sure that any service defines are reflected in policy so that proper service
    /// attributes get set up at connect time.
    fn defines_to_services(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        for define in &policy.defines {
            if define.flavor != ClassFlavor::Service {
                continue;
            }
            // An actor can connect and offer the service if it is able to satisfy the
            // set of attributes attached to it through the define or configuration.
            //
            // TODO: If there are no allow rules that permit access to the service then
            // maybe we don't even allow it to connect?
            let mut attrs = Vec::new();
            let svc_class_attrs = attrs_for_class(class_idx, &define.name);
            attrs.extend_from_slice(&svc_class_attrs);
            self.add_service(class_idx, define, &attrs, define.class_id, config)?;
        }
        Ok(())
    }

    fn add_service(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        sclass: &Class,
        initial_attrs: &[Attribute],
        svc_id: usize,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        let service_name = &sclass.name;
        let mut attrs = Vec::new();
        attrs.extend_from_slice(initial_attrs);

        // Service class either match an ID in the configuration or must have a
        // parent that does.  We take the first parent that matches a configuration as
        // the service configuration to use.
        //

        let matched_service_name = find_defined_service(service_name, config, class_idx);
        if matched_service_name.is_none() {
            return Err(CompilationError::ConfigError(format!(
                "no service for {} found in configuration",
                service_name
            )));
        }
        let matched_service_name = matched_service_name.unwrap();

        // The service may have provider attributes that we need.
        match config.get(&format!("/services/{}/provider", matched_service_name)) {
            Some(citem) => match citem {
                ConfigItem::AttrList(alist) => {
                    attrs.extend_from_slice(&vec_to_attributes(&alist)?);
                }
                _ => {
                    panic!("error: provider must be an attribute list");
                }
            },
            None => {
                // no provider attributes
            }
        };

        // service must have a protocol
        let prot = match config.get(&format!("/services/{}/protocol", matched_service_name)) {
            Some(citem) => match &citem {
                ConfigItem::Protocol(_, _, _) => Protocol::from(citem),
                _ => {
                    panic!("error: protocol must be a protocol enum");
                }
            },
            None => {
                return Err(CompilationError::ConfigError(format!(
                    "protocol for {} not found in configuration",
                    matched_service_name,
                )));
            }
        };

        // This service may be an adapter facing authentication service.
        let mut svc_type = ServiceType::Regular;
        match config.get("/trusted_services") {
            Some(ConfigItem::KeySet(ts_names)) => {
                for nam in ts_names {
                    match config.get(&format!("/trusted_services/{nam}/client_service")) {
                        Some(ConfigItem::StrVal(cs_name)) if cs_name == matched_service_name => {
                            svc_type = ServiceType::Authentication;
                            break;
                        }
                        _ => (),
                    }
                }
            }
            _ => (),
        };

        let attr_map = squash_attributes(&attrs, &sclass.pos)?;
        let resolved_attrs = self.resolve_attributes(
            attr_map
                .into_values()
                .collect::<Vec<Attribute>>()
                .as_slice(),
            config,
        )?;

        if svc_type == ServiceType::Regular && resolved_attrs.is_empty() {
            return Err(CompilationError::ConfigError(format!(
                "service with no attributes {}",
                matched_service_name
            )));
        }

        let fabric_svc_id =
            self.fabric
                .add_service(&matched_service_name, &prot, &resolved_attrs, svc_type)?;
        self.allowid_to_fab_svc.insert(svc_id, fabric_svc_id);

        Ok(())
    }

    /// This requires that `add_services` has already been run.
    ///
    /// Panics if
    /// * `name` is not in the `class_idx`
    /// * the class ID for `name` is not in the fabric services map.
    fn service_clause_name_to_fabric_id(
        &self,
        class_idx: &HashMap<String, &Class>,
        name: &str,
    ) -> String {
        let svc_id = match class_idx.get(name) {
            Some(cls) => cls.class_id,
            None => panic!("service class {} not found in class index", name),
        };
        let fab_svc_id = match self.allowid_to_fab_svc.get(&svc_id) {
            Some(s) => s,
            None => {
                // programming error
                panic!(
                    "error - service {} with id {} not found in map",
                    name, svc_id
                );
            }
        };
        fab_svc_id.clone()
    }

    fn allow_clauses_to_services(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        for ac in &policy.allows {
            // Parser ensures that the allow clause has a server.service clause.
            let server_service = ac.get_server_service_clause().unwrap();
            if server_service.class == zpl::DEF_CLASS_SERVICE_NAME {
                // ZPL that applies to ALL services does not generate additional
                // connect rules.  But it will create access rules.
                continue;
            }
            if server_service.class == zpl::DEF_CLASS_VISA_SERVICE_NAME {
                // Handled elswhere.
                continue;
            }

            let svc_id = match class_idx.get(&server_service.class) {
                Some(cls) => cls.class_id,
                None => panic!(
                    "service class {} not found in class index",
                    server_service.class
                ),
            };

            // start with parent class attributes
            let mut attrs = attrs_for_class(class_idx, &server_service.class);

            // And include any additionaal server side attributes from the RHS clause.
            for rhs_clause in &ac.server {
                attrs.extend_from_slice(&rhs_clause.with);
            }
            let svc_class = class_idx
                .get(&server_service.class)
                .expect("service class not found in class index");
            self.add_service(class_idx, svc_class, &attrs, svc_id, config)?;
        }
        Ok(())
    }

    // Every attribute needs to come from a trusted service.
    //
    // As a side effect, this updates our local set of in-use trusted services.
    //
    fn resolve_attributes(
        &mut self,
        attrs: &[Attribute],
        config: &ConfigApi,
    ) -> Result<Vec<Attribute>, CompilationError> {
        let trusted_service_names = config.must_get_keys("/trusted_services");

        let mut resolved_attrs = Vec::new();
        for zpl_attr in attrs {
            let attr_name = zpl_attr.zpl_key();
            if zpl_attr.is_tag() && zpl_attr.zpl_value() == zpl::KATTR_CN {
                return Err(CompilationError::ConfigError(format!(
                    "{} attribute used as a tag, but is a tuple attribute",
                    zpl_attr,
                )));
            }

            match attr_name.as_str() {
                zpl::KATTR_CN => {
                    resolved_attrs.push(zpl_attr.clone());
                    self.used_trusted_services
                        .insert(zpl::DEFAULT_TRUSTED_SERVICE_ID.to_string());
                }
                zpl::DEFAULT_ATTR => {
                    resolved_attrs.push(zpl_attr.clone_with_new_name(zpl::KATTR_CN));
                    self.used_trusted_services
                        .insert(zpl::DEFAULT_TRUSTED_SERVICE_ID.to_string());
                }
                zpl::KATTR_SERVICES => {
                    resolved_attrs.push(zpl_attr.clone());
                    self.used_trusted_services
                        .insert(zpl::DEFAULT_TRUSTED_SERVICE_ID.to_string());
                }
                _ => {
                    // TODO: This should be cached
                    // TODO: Not sure we are handling the case where ZPL is using prefixes correctly here.
                    let mut matched = false;
                    for ts_name in &trusted_service_names {
                        let ts_attrs = config.must_get_attr_map(&format!(
                            "/trusted_services/{}/attributes",
                            ts_name
                        ));

                        // "a" is the attribute referenced in the ZPL, so this will turn up on the RIGHT side of the map.
                        // The left side (the strings) are the names of the raw attributes returned by the service.

                        // As we search we need to consider that a tuple type attribute could match
                        // either the service plain key eg, "user.role" or the service multi-value key, eg, "user.role{}".
                        let search_str = zpl_attr.zplc_key();
                        let alt_search_str = if !zpl_attr.is_tag() && !zpl_attr.is_multi_valued() {
                            Some(format!("{}{{}}", search_str))
                        } else {
                            None
                        };

                        let found = ts_attrs.iter().find(|(_k, v)| {
                            v.zplc_key() == search_str
                                || alt_search_str.is_some()
                                    && &v.zplc_key() == alt_search_str.as_ref().unwrap()
                        });

                        //if ts_attrs.contains(&search_name) {
                        if let Some((_svcname, attr_spec)) = found {
                            if matched {
                                return Err(CompilationError::ConfigError(format!(
                                    "attribute {zpl_attr} found in multiple trusted services"
                                )));
                            }
                            let mut new_attr = zpl_attr.clone();
                            // If the service indicates that this attribute is multi-valued then we keep that info.
                            if attr_spec.is_multi_valued() {
                                new_attr.set_multi_valued();
                            }
                            resolved_attrs.push(new_attr);
                            self.used_trusted_services.insert(ts_name.clone());
                            matched = true;
                        }
                    }
                    if !matched {
                        return Err(CompilationError::ConfigError(format!(
                            "attribute {zpl_attr} not found in any trusted service"
                        )));
                    }
                }
            }

            if attr_name == zpl::KATTR_CN {
            } else if attr_name == zpl::DEFAULT_ATTR {
            } else {
            }
        }
        Ok(resolved_attrs)
    }

    /// Must init_services before init_nodes.
    fn init_nodes(&mut self, config: &ConfigApi) -> Result<(), CompilationError> {
        let node_keys = match config.get("zpr/nodes") {
            Some(ConfigItem::KeySet(node_ids)) => node_ids,
            _ => {
                return Err(CompilationError::ConfigError(
                    "no nodes defined in configuration".to_string(),
                ));
            }
        };

        if node_keys.len() > 1 {
            return Err(CompilationError::ConfigError(
                "multiple nodes defined in configuration".to_string(),
            ));
        }
        let vs_dock_node = match config.get("zpr/visa_services/default/dock_node_id") {
            Some(ConfigItem::StrVal(node_id)) => node_id,
            _ => {
                return Err(CompilationError::ConfigError(
                    "visa service docking node not defined for default VS in configuration"
                        .to_string(),
                ));
            }
        };
        if vs_dock_node != node_keys[0] {
            return Err(CompilationError::ConfigError(format!(
                "visa service docking node must be the only node in configuration: '{}' != '{}'",
                vs_dock_node, node_keys[0]
            )));
        }

        // Before handing off to fabric, we need to check the node provider attributes to see
        // if they reference any trusted services.
        for node_key in &node_keys {
            let node_attrs = match config.get(&format!("zpr/nodes/{node_key}/provider")) {
                Some(ConfigItem::AttrList(attrs)) => vec_to_attributes(&attrs)?,
                _ => {
                    return Err(CompilationError::ConfigError(format!(
                        "node {node_key} missing provider attributes",
                    )));
                }
            };
            // We don't care here what the attributes are (the fabric calls for them itself), we just want
            // to make sure they all resolve.
            let _ = self.resolve_attributes(&node_attrs, config)?;
        }

        self.fabric.add_node(&vs_dock_node, config)
    }

    /// Process the ZPL policy into conditions for accessing fabric services.
    /// Must be done after initializing the services.
    fn add_client_allow_policies(
        &mut self,
        comp: &Compilation,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        // Every allow is an access condition (aka rule, aka policy).
        // We need the attributes from the user and device clauses.
        self.add_client_policies_allow_or_deny(comp, &policy.allows, false, class_idx, config)
    }

    fn add_client_deny_policies(
        &mut self,
        comp: &Compilation,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        // Every allow is an access condition (aka rule, aka policy).
        // We need the attributes from the user and device clauses.
        self.add_client_policies_allow_or_deny(comp, &policy.nevers, true, class_idx, config)
    }

    fn add_client_policies_allow_or_deny(
        &mut self,
        comp: &Compilation,
        allow_clause: &[AllowClause],
        never_allow: bool,
        class_idx: &HashMap<String, &Class>,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        for (i, ac) in allow_clause.iter().enumerate() {
            let server_service = ac.get_server_service_clause().unwrap();
            if server_service.class == zpl::DEF_CLASS_VISA_SERVICE_NAME {
                // Visa service is handled separately.
                continue;
            }

            // Here we collect all attributes -- some will have no values.
            let mut attrs = Vec::new();

            // Grab the LHS endpoint, service and user attributes.
            for lhs_class in &ac.client {
                if lhs_class.flavor == ClassFlavor::Endpoint
                    || lhs_class.flavor == ClassFlavor::User
                    || lhs_class.flavor == ClassFlavor::Service
                {
                    // Add attributes from parent
                    attrs.extend_from_slice(&attrs_for_class(class_idx, &lhs_class.class));

                    // Add non-optional instance attributes
                    attrs.extend(lhs_class.with.iter().filter(|a| !a.optional).cloned());

                    // If there is a service clause on the LHS then we assert that the
                    // connecting client is a provider of that service. Note, there may not
                    // be a concrete service specified, in that case we just say client must be
                    // a provider of ANY service.
                    if lhs_class.flavor == ClassFlavor::Service {
                        let svc_attr = if lhs_class.class == zpl::DEF_CLASS_SERVICE_NAME {
                            Attribute::must_zpr_internal_attr_mv(zpl::KATTR_SERVICES, "")
                        } else {
                            let fab_svc_name =
                                self.service_clause_name_to_fabric_id(class_idx, &lhs_class.class);
                            Attribute::must_zpr_internal_attr_mv(zpl::KATTR_SERVICES, &fab_svc_name)
                        };
                        attrs.push(svc_attr);
                    }
                }
            }

            // Now we consolidate the attributes into a map, preferring attributes that have a value.
            let fp = FPos::from(server_service.class_tok);
            let attr_map = squash_attributes(&attrs, &fp)?;
            let required_attrs = self
                .resolve_attributes(&attr_map.into_values().collect::<Vec<Attribute>>(), config)?;

            // Now grab the RHS attributes (attributes for the server)
            let svc_required_attrs = {
                let mut service_class_attrs = Vec::new();
                for rhs_class in &ac.server {
                    service_class_attrs
                        .extend(rhs_class.with.iter().filter(|a| !a.optional).cloned());
                }
                let attr_map = squash_attributes(&service_class_attrs, &fp)?;
                self.resolve_attributes(
                    &attr_map.into_values().collect::<Vec<Attribute>>(),
                    config,
                )?
            };

            // Now figure out what service we are talking about.
            // The service may be:
            // a) a service that is defined in configuration, eg "SomeDatabase"
            // b) a service that is defined in ZPL as a child of a service defined in configuration.
            // c) the base service, eg, "service" - "allow red users to access services" -- in which case this condition applied to
            //    all services.

            let pline = PLine {
                lineno: ac.span.0.line,
                zpl: if never_allow {
                    comp.zpl_for_never_allow_statement(i)
                } else {
                    comp.zpl_for_allow_statement(i)
                },
            };

            if server_service.class == zpl::DEF_CLASS_SERVICE_NAME {
                // Add to all services (not nodes or trusted services or visa service)
                self.fabric.add_condition_to_all_services(
                    never_allow,
                    &required_attrs,
                    &svc_required_attrs,
                    ac.signal.clone(),
                    &pline,
                )?;
            } else {
                let fab_svc_id =
                    self.service_clause_name_to_fabric_id(class_idx, &server_service.class);
                self.fabric.add_condition_to_service(
                    never_allow,
                    &fab_svc_id,
                    &required_attrs,
                    &svc_required_attrs,
                    false,
                    ac.signal.clone(),
                    &pline,
                )?;
            }
        }
        Ok(())
    }

    /// For now we only accept the DEFAULT (builtin) trusted service.
    /// And the only thing we care about is the certificate.
    fn add_default_auth(
        &mut self,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        if config
            .get(&format!(
                "/trusted_services/{}",
                zpl::DEFAULT_TRUSTED_SERVICE_ID
            ))
            .is_none()
        {
            return Err(CompilationError::ConfigError(
                "no trusted default service found in configuration".to_string(),
            ));
        }

        let cert_data = match config.get(&format!(
            "/trusted_services/{}/certificate",
            zpl::DEFAULT_TRUSTED_SERVICE_ID
        )) {
            Some(ConfigItem::BytesB64(b64data)) => match BASE64_STANDARD.decode(b64data) {
                Ok(cert_data) => cert_data,
                Err(e) => {
                    return Err(CompilationError::ConfigError(format!(
                        "error decoding certificate data: {}",
                        e
                    )));
                }
            },
            _ => {
                // TODO: This should probably be an error, but helps for testing.
                ctx.warn("no certificate for default trusted service")?;
                vec![]
            }
        };

        self.fabric.default_auth_cert_asn = cert_data;
        Ok(())
    }

    /// Check that the providers of trusted services are expressed using attributes that
    /// we know the source of.  This may add to the list of active trusted services --
    /// since it's possible that some trusted services are only used when defining other
    /// trusted services.
    fn resolve_trusted_service_providers(
        &mut self,
        config: &ConfigApi,
        _ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        let mut checked_services = HashSet::new();
        loop {
            let active_set_count = self.used_trusted_services.len();
            let active_trusted_services = self.used_trusted_services.clone();
            for ts_name in &active_trusted_services {
                if ts_name == zpl::DEFAULT_TRUSTED_SERVICE_ID {
                    continue;
                }
                if checked_services.contains(ts_name) {
                    continue;
                }
                checked_services.insert(ts_name.clone());
                let ts_provider_attrs =
                    match config.get(&format!("/trusted_services/{ts_name}/provider")) {
                        Some(ConfigItem::AttrList(attrs)) => vec_to_attributes(&attrs)?,
                        _ => {
                            return Err(CompilationError::ConfigError(format!(
                                "trusted service {ts_name} missing provider attributes",
                            )));
                        }
                    };

                // Call resolve which may add to the list of active trusted services.
                let _ = self.resolve_attributes(&ts_provider_attrs, config)?;
            }
            if self.used_trusted_services.len() == active_set_count {
                break; // no change? We are done.
            }
        }
        Ok(())
    }

    /// Add non-default trusted services to the fabric.
    fn add_trusted_services(
        &mut self,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        self.resolve_trusted_service_providers(config, ctx)?;

        // Copy the used trusted service names into a stand alone vector to avoid
        // holding an immutable ref to self in the following loop.
        let used_trusted_service_names = self.used_trusted_services.clone();

        for ts_name in used_trusted_service_names {
            if ts_name == zpl::DEFAULT_TRUSTED_SERVICE_ID {
                continue;
            }

            let ts_api = config
                .must_get(&format!("/trusted_services/{ts_name}/api"))
                .to_string();
            let client_svc = config
                .must_get(&format!("/trusted_services/{ts_name}/client_service"))
                .to_string();
            let vs_svc = config
                .must_get(&format!("/trusted_services/{ts_name}/vs_service"))
                .to_string();
            let ts_cert = match config.get(&format!("/trusted_services/{ts_name}/certificate")) {
                Some(ConfigItem::BytesB64(b64data)) => match BASE64_STANDARD.decode(b64data) {
                    Ok(cert_data) => Some(cert_data),
                    Err(e) => {
                        return Err(CompilationError::ConfigError(format!(
                            "error decoding certificate data: {}",
                            e
                        )));
                    }
                },
                _ => None,
            };
            let ts_provider_attrs =
                match config.get(&format!("/trusted_services/{ts_name}/provider")) {
                    Some(ConfigItem::AttrList(attrs)) => vec_to_attributes(&attrs)?,
                    _ => {
                        return Err(CompilationError::ConfigError(format!(
                            "trusted service {ts_name} missing provider attributes",
                        )));
                    }
                };

            let vs_svc_protocol = self.check_ts_components(
                config,
                ctx,
                &ts_name,
                &client_svc,
                &vs_svc,
                &ts_api,
                &ts_provider_attrs,
            )?;

            // The trusted service must return some attributes, and may return some identity attributes.
            let ts_returns_attrs =
                match config.get(&format!("/trusted_services/{ts_name}/attributes")) {
                    Some(ConfigItem::AttributeMap(map)) => map,
                    _ => {
                        return Err(CompilationError::ConfigError(format!(
                            "trusted service {} missing return attributes",
                            ts_name
                        )));
                    }
                };
            let ts_identity_attrs =
                match config.get(&format!("/trusted_services/{ts_name}/id_attributes")) {
                    Some(ConfigItem::KeySet(attrs)) => Some(attrs),
                    _ => None,
                };

            if vs_svc_protocol.is_none() {
                return Err(CompilationError::ConfigError(format!(
                    "trusted service {} missing visa service facing service protocol",
                    ts_name
                )));
            }
            self.fabric
                .add_trusted_service(
                    &ts_name,
                    &vs_svc_protocol.unwrap(),
                    &ts_api,
                    &ts_provider_attrs,
                    ts_cert,
                    &client_svc,
                    Some(ts_returns_attrs),
                    ts_identity_attrs,
                )
                .map_err(|e| {
                    CompilationError::ConfigError(format!("error adding trusted service: {}", e))
                })?;

            // The visa service can access the trusted service over its vs interface.
            let vs_access_attrs = vec![Attribute::must_new_single_valued(
                zpl::KATTR_CN,
                zpl::VISA_SERVICE_CN,
            )];
            let pline = PLine::new_builtin(&format!(
                "allow visa service access to trusted service {}",
                ts_name
            ));
            self.fabric.add_condition_to_service(
                false,
                &ts_name,
                &vs_access_attrs,
                &[],
                true,
                None,
                &pline,
            )?;
        }
        Ok(())
    }

    /// Check the details around the two components of a trusted service: the visa-facing and the
    /// actor/adapter facing.
    ///
    /// Returns the protocol for the visa-facing component of the trusted service (if found).
    ///
    /// As a side effect this also will update the actor/adapter facing service record in the fabric
    /// with the protocol and provider attributes.
    fn check_ts_components(
        &mut self,
        config: &ConfigApi,
        ctx: &CompilationCtx,
        ts_name: &str,
        client_svc: &str,
        vs_svc: &str,
        ts_api: &str,
        ts_provider_attrs: &Vec<Attribute>,
    ) -> Result<Option<Protocol>, CompilationError> {
        let mut vs_svc_protocol: Option<Protocol> = None;
        for svc_name in [client_svc, vs_svc] {
            if self.fabric.has_service(svc_name) {
                if svc_name == vs_svc {
                    panic!("error: visa service should not yet exist in fabric");
                }
            } else if svc_name == client_svc {
                // This implies that there is no ZPL allowing access to the client facing
                // authentication service.  Warn user.
                // TODO: This is actually perfectly fine if the service only supports query.
                ctx.warn(&format!(
                    "no ZPL policy allowing access to client authentication service {}",
                    client_svc
                ))?;
                continue;
            }
            // service must have a protocol
            let prot = match config.get(&format!("/services/{svc_name}/protocol")) {
                Some(citem) => match &citem {
                    ConfigItem::Protocol(_, _, _) => Protocol::from(citem),
                    _ => {
                        panic!("error: protocol must be a protocol enum");
                    }
                },
                None => {
                    return Err(CompilationError::ConfigError(format!(
                        "protocol for service {} not found in configuration",
                        svc_name,
                    )));
                }
            };
            if svc_name == vs_svc {
                let mut vsp = prot.clone();
                if ts_api == zpl::TS_API_V2 {
                    // Since we do not get layer7 from the config api, we set it here.
                    // TODO: Pass the layer7 info across the api boundry.
                    vsp.set_layer7(ZPR_VALIDATION_2.to_string());
                } else {
                    return Err(CompilationError::ConfigError(format!(
                        "trusted service {} has unknown API version {}",
                        ts_name, ts_api
                    )));
                }
                vs_svc_protocol = Some(vsp);
            } else {
                // Fold in additional details about the client facing authentication service.
                let mut auth_prot = prot.clone();
                auth_prot.set_layer7(ZPR_OAUTH_RSA.to_string()); // TODO: Return layer7 name from config_api. Hardcoded to "zpr-oauthrsa" for now.
                let found = self.fabric.update_service(svc_name, |svc| {
                    svc.protocol = Some(auth_prot.clone());
                    svc.provider_attrs = ts_provider_attrs.clone();
                    svc.service_type = ServiceType::Authentication;
                });
                if !found {
                    // Programming error we checked above that the service was in the fabcir.
                    panic!("error: service {} not found in fabric", svc_name);
                }
            }
        }
        Ok(vs_svc_protocol)
    }

    fn add_bootstrap_records(
        &mut self,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        let bootstrap_cns = match config.get("zpr/bootstrap") {
            Some(ConfigItem::KeySet(cns)) => cns,
            _ => Vec::new(),
        };
        for cnval in &bootstrap_cns {
            match config.get(&format!("zpr/bootstrap/{cnval}")) {
                Some(ConfigItem::BytesB64(b64data)) => match BASE64_STANDARD.decode(b64data) {
                    Ok(cert_data) => {
                        self.fabric
                            .bootstrap_records
                            .insert(cnval.clone(), cert_data.clone());
                    }
                    Err(e) => {
                        return Err(CompilationError::ConfigError(format!(
                            "error decoding certificate data: {}",
                            e
                        )));
                    }
                },
                item @ Some(_) => {
                    return Err(CompilationError::ConfigError(format!(
                        "unexpected result from config: expected certificate data got {:?}",
                        item
                    )));
                }
                None => {
                    ctx.warn(&format!("no certificate for bootstrap record {}", cnval))?;
                }
            }
        }
        Ok(())
    }
}

/// Returns first service starting with `class_name` and searching ancestors that is
/// defined in our service index (ie, is in configuration).
fn find_defined_service(
    class_name: &str,
    config: &ConfigApi,
    class_idx: &HashMap<String, &Class>,
) -> Option<String> {
    let mut cur_svc_class = class_name;
    let mut matched_service = config.get(&format!("/services/{}", cur_svc_class));

    while matched_service.is_none() {
        let cl = class_idx.get(cur_svc_class).unwrap();
        if cl.parent == cl.name {
            // we are at top of hierarchy
            break;
        }
        cur_svc_class = &cl.parent;
        matched_service = config.get(&format!("/services/{}", cur_svc_class));
    }
    matched_service.map(|s| s.to_string())
}

/// Get all the WITH attributes on the named class, including any attributes on
/// the parent classes.  We ignore optional attributes.
fn attrs_for_class(class_idx: &HashMap<String, &Class>, class_name: &str) -> Vec<Attribute> {
    let mut attrs = Vec::new();
    let mut cl = class_idx
        .get(class_name)
        .unwrap_or_else(|| panic!("class {} not found in class index", class_name));

    // If my parent name is not my name... grab all my attributes.
    while cl.parent != cl.name {
        for a in &cl.with_attrs {
            if a.optional {
                continue;
            }
            attrs.push(a.clone());
        }
        // Then move up to the parent class.
        cl = class_idx
            .get(&cl.parent)
            .unwrap_or_else(|| panic!("error parent class {} of {} not found", cl.parent, cl.name));
    }
    // WHEN parent name is my name, take my attributes
    for a in &cl.with_attrs {
        if a.optional {
            continue;
        }
        attrs.push(a.clone());
    }
    attrs
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::context::CompilationCtx;
    use crate::lex::Token;
    use crate::ptypes::{AllowClause, ClassFlavor, Clause, FPos};
    use std::env;
    use std::path::PathBuf;

    #[test]
    fn test_init_services_minimal() {
        let cfg = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["foo", "fee"]]

        [visa_service]
        dock_node = "n0"
        "#;

        let mut w = Weaver::new();
        let class_idx = HashMap::new();
        let policy = Policy::default();
        let config =
            ConfigApi::new_from_toml_content(&cfg, &env::temp_dir(), &CompilationCtx::default())
                .expect("failed to parse config");
        let comp = Compilation::builder(PathBuf::default()).build();

        let res = w.init_services(
            &comp,
            &class_idx,
            &policy,
            &config,
            &CompilationCtx::default(),
        );
        assert!(res.is_ok());

        // Should create two services: visa-service and visa-service-admin
        assert_eq!(w.fabric.services.len(), 2);

        let vs = w
            .fabric
            .services
            .iter()
            .find(|s| s.fabric_id == zpl::VS_SERVICE_NAME);
        assert!(vs.is_some());

        let vs = w
            .fabric
            .services
            .iter()
            .find(|s| s.fabric_id == format!("{}/admin", zpl::VS_SERVICE_NAME));
        assert!(vs.is_some());
    }

    #[test]
    fn test_init_services_must_be_in_zpl() {
        let cfg = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["endpoint.zpr.adapter.cn", "fee"]]

        [visa_service]
        dock_node = "n0"

        [protocols.fee]
        l4protocol = "iana.TCP"
        port = 80

        [services.foo]
        protocol = "fee"
        provider = [["endpoint.zpr.adapter.cn", "fee"]]

        [services.bar]
        protocol = "fee"
        "#;

        let mut class_idx = HashMap::new();
        let mut policy = Policy::default();
        let ctx = CompilationCtx::default();
        let config = ConfigApi::new_from_toml_content(&cfg, &env::temp_dir(), &ctx)
            .expect("failed to parse config");
        let comp = Compilation::builder(PathBuf::default()).build();

        {
            let mut w = Weaver::new();

            let res = w.init_services(&comp, &class_idx, &policy, &config, &ctx);
            assert!(res.is_ok(), "init_services failed: {}", res.unwrap_err());

            // Should create two services: visa-service and visa-service-admin.
            // Does not create services just because they are in the config.
            assert_eq!(w.fabric.services.len(), 2);
            let vs = w
                .fabric
                .services
                .iter()
                .find(|s| s.fabric_id == zpl::VS_SERVICE_NAME);
            assert!(vs.is_some());
            let vs = w
                .fabric
                .services
                .iter()
                .find(|s| s.fabric_id == format!("{}/admin", zpl::VS_SERVICE_NAME));
            assert!(vs.is_some());
        }

        // But will create services if they are in the ZPL.

        // We are only calling init_services which does not create policies anyway.
        // Will only notice that the 'foo' service is referenced.
        let a_foo = AllowClause {
            clause_id: 1,
            span: (FPos::default(), FPos::default()),
            client: vec![
                Clause::new(ClassFlavor::Endpoint, "endpoint", Token::default()),
                Clause::new(ClassFlavor::User, "user", Token::default()),
            ],
            server: vec![Clause::new(ClassFlavor::Service, "foo", Token::default())],
            signal: None,
        };
        policy.allows.push(a_foo);

        // Class named "foo" must have been parsed.
        let defaults = Class::defaults();
        for def_cl in &defaults {
            class_idx.insert(def_cl.name.clone(), def_cl);
        }
        let foo_cls = Class {
            flavor: ClassFlavor::Service,
            parent: zpl::DEF_CLASS_SERVICE_NAME.to_string(),
            name: "foo".to_string(),
            aka: "foos".to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
            extensible: true,
            class_id: 100,
        };
        class_idx.insert("foo".to_string(), &foo_cls);

        {
            let mut w = Weaver::new();
            let res = w.init_services(&comp, &class_idx, &policy, &config, &ctx);
            println!("{:?}", res);
            assert!(res.is_ok(), "init_services failed: {}", res.unwrap_err());
            assert_eq!(w.fabric.services.len(), 3);
            let vs = w.fabric.services.iter().find(|s| s.fabric_id == "foo");
            assert!(vs.is_some());
        }
    }

    #[test]
    fn test_reads_return_and_id_attrs() {
        let cfg = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["endpoint.zpr.adapter.cn", "fee"]]

        [visa_service]
        dock_node = "n0"

        [trusted_services.bas]
        api = "validation/2"
        provider = [["endpoint.zpr.adapter.cn", "fee"]]
        returns_attributes = ["id -> user.id", "email -> user.email"]
        identity_attributes = ["id"]

        [services.bas-vs]
        protocol = "zpr-validation2"
        port = 3999

        [services.bas-client]
        protocol = "zpr-oauthrsa"
        port = 3998

        "#;

        let ctx = CompilationCtx::default();
        let config = ConfigApi::new_from_toml_content(&cfg, &env::temp_dir(), &ctx)
            .expect("failed to parse config");

        let mut w = Weaver::new();
        w.used_trusted_services.insert("bas".to_string()); // Add the trusted service to the used set.
        let res = w.add_trusted_services(&config, &ctx);
        assert!(
            res.is_ok(),
            "add_trusted_services failed: {}",
            res.unwrap_err()
        );

        // Will create the trusted service.
        assert_eq!(w.fabric.services.len(), 1);

        let fsvc = &w.fabric.services[0];
        assert_eq!(fsvc.fabric_id, "bas");
        let return_attrs = fsvc.returns_attrs.as_ref().unwrap();
        assert_eq!(return_attrs.len(), 2);
        assert!(return_attrs["id"].to_string() == "user.id");
        assert!(return_attrs["email"].to_string() == "user.email");
        let id_attrs = fsvc.identity_attrs.as_ref().unwrap();
        assert_eq!(id_attrs.len(), 1);
        assert!(id_attrs.contains(&String::from("id")));
    }
}
