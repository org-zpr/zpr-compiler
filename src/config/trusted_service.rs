//! Parser for the `trusted_services` TOML section and its attribute-mapping syntax.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use toml::Table;
use zpr::policy_types::Attribute;

use crate::context::CompilationCtx;
use crate::err_config;
use crate::errors::CompilationError;
use crate::zpl;

use super::{TrustedService, parse_provider};

fn warn_unknown_ts_property(ts: &Table, ctx: &CompilationCtx) -> Result<(), CompilationError> {
    for elem in ts.keys() {
        match elem.as_str() {
            "cert_path" => (),
            "api" => (),
            "client" => (),
            "service" => (),
            "returns_attributes" => (),
            "provider" => (),
            "prefix" => (),
            "identity_attributes" => (),
            _ => ctx.warn(&format!(
                "unknown property '{elem}' detected while parsing trusted_services",
            ))?,
        }
    }
    Ok(())
}

/// Parse table entry `key` as a string array.  If key is not found returns empty vector.
fn parse_string_array(ts: &Table, key: &str, ctx: &str) -> Result<Vec<String>, CompilationError> {
    if !ts.contains_key(key) {
        return Ok(Vec::new());
    }
    let arr = ts[key]
        .as_array()
        .ok_or(err_config!("{} {} is not an array", ctx, key))?;
    let mut ret = Vec::new();
    for a in arr {
        ret.push(
            a.as_str()
                .ok_or(err_config!("{} {} array entry is not a string", ctx, key))?
                .to_string(),
        );
    }
    Ok(ret)
}

// Parse an individual trusted_service table.
pub(super) fn parse_trusted_service(
    ts_id: &str,
    ts: &Table,
    ctx: &CompilationCtx,
) -> Result<TrustedService, CompilationError> {
    warn_unknown_ts_property(ts, ctx)?;
    // The "api" value is optional for the default trusted service.
    let mut is_default = false;
    let api = if ts.contains_key("api") {
        ts["api"]
            .as_str()
            .ok_or(err_config!("trusted_service {} missing api", ts_id))?
            .to_string()
    } else if ts_id == zpl::DEFAULT_TRUSTED_SERVICE_ID {
        is_default = true;
        zpl::DEFAULT_TRUSTED_SERVICE_API.to_string()
    } else {
        return Err(err_config!("trusted_service {} missing api", ts_id));
    };
    let cert_path = if ts.contains_key("cert_path") {
        Some(PathBuf::from(ts["cert_path"].as_str().ok_or(
            err_config!("trusted_service {} cert_path is not a string", ts_id),
        )?))
    } else if is_default {
        // The path is the only thing required for the default section.
        ctx.warn("no cert_path for default trusted_service, certificate checking disabled")?;
        None
    } else {
        None
    };

    let returns_attrs: Vec<String>;
    let identity_attrs: Vec<String>;
    let client_svc: Option<String>;
    let service_svc: Option<String>;
    if !is_default {
        returns_attrs = parse_string_array(ts, "returns_attributes", "trusted_service")?;
        identity_attrs = parse_string_array(ts, "identity_attributes", "trusted_service")?;

        if ts.contains_key("client") {
            client_svc = Some(
                ts["client"]
                    .as_str()
                    .ok_or(err_config!("trusted_service {} client parse error", ts_id))?
                    .to_string(),
            );
        } else {
            client_svc = Some(format!("{}-client", ts_id));
        }
        if ts.contains_key("service") {
            service_svc = Some(
                ts["service"]
                    .as_str()
                    .ok_or(err_config!("trusted_service {} service parse error", ts_id))?
                    .to_string(),
            );
        } else {
            service_svc = Some(format!("{}-vs", ts_id));
        }
    } else {
        if ts.contains_key("returns_attributes") {
            return Err(err_config!(
                "default trusted_service does not allow custom returns_attributes"
            ));
        }
        if ts.contains_key("identity_attributes") {
            return Err(err_config!(
                "default trusted_service does not allow custom identity_attributes"
            ));
        }
        returns_attrs = vec![format!("{} -> {}", zpl::KATTR_CN, zpl::KATTR_CN)];
        identity_attrs = vec![String::from(zpl::KATTR_CN)];
        client_svc = None;
        service_svc = None;
    }

    let mut returns = HashMap::new();
    for ra in &returns_attrs {
        let (service_key_name, zpr_attr) = parse_attribute_mapping(ra)?;
        if returns.contains_key(&service_key_name) {
            return Err(err_config!(
                "trusted_service {} contains duplicate service attribute name '{}'",
                ts_id,
                service_key_name
            ));
        }
        returns.insert(service_key_name, zpr_attr);
    }

    let mut idents = Vec::new();
    for ra in &identity_attrs {
        // The ident attribute (for now) must exist in the returns attributes.
        if !returns.contains_key(ra) {
            return Err(err_config!(
                "trusted_service {} identity attribute '{}' not in returns_attributes",
                ts_id,
                ra
            ));
        }
        idents.push(ra.to_string());
    }

    let provider = if ts.contains_key("provider") {
        Some(parse_provider(&format!("trusted_service {ts_id}"), ts)?)
    } else {
        if !is_default {
            return Err(err_config!("trusted_service {} missing provider", ts_id));
        }
        None
    };

    Ok(TrustedService {
        id: ts_id.to_string(),
        api,
        cert_path,
        returns_attrs: returns,
        identity_attrs: idents,
        provider,
        client: client_svc,
        service: service_svc,
    })
}

/// The mapping string format is "<service-key-name> -> <attribute-spec>" where attribute
/// spec is:
///   - <class-name>.<attribute-name> for a regular single value attribute.
///   - #<class-name>.<attribute-name> for a tag attribute.
///   - <class-name>.<attribute-name>{} for a multi-valued attribute.
///
/// Note that we never use "optional" flag in ZPLC.
pub(super) fn parse_attribute_mapping(
    mapping: &str,
) -> Result<(String, Attribute), CompilationError> {
    let parts: Vec<&str> = mapping.split("->").collect();
    if parts.len() != 2 {
        return Err(err_config!(
            "invalid attribute mapping '{}', must be of the form '<service-key-name> -> <attribute-spec>'",
            mapping
        ));
    }
    let service_key_name = parts[0].trim().to_string();
    let attr_spec = parts[1].trim();

    let zpr_attr = if let Some(stripped) = attr_spec.strip_prefix("#") {
        Attribute::tag(stripped).build()?
    } else if let Some(stripped) = attr_spec.strip_suffix("{}") {
        Attribute::tuple(stripped).multi().build()?
    } else {
        Attribute::tuple(attr_spec).single().build()?
    };

    // In theory we can support any attribute names if they are quoted.
    // But until we support that on VS we will not permit some characters
    // here.
    let valid_chars: HashSet<char> =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./"
            .chars()
            .collect();
    for c in zpr_attr.zpl_key().chars() {
        if !valid_chars.contains(&c) {
            return Err(err_config!(
                "invalid attribute name '{}' in mapping '{}', contains invalid character '{}'",
                zpr_attr.zpl_key(),
                mapping,
                c
            ));
        }
    }

    Ok((service_key_name, zpr_attr))
}

#[cfg(test)]
mod test {
    use super::*;
    use zpr::policy_types::AttrDomain;

    #[test]
    fn test_parse_attribute_mapping_tag() {
        let mapping = "service_key -> #endpoint.tag";
        let result = parse_attribute_mapping(mapping);

        assert!(result.is_ok());
        let (service_key_name, attr) = result.unwrap();

        assert_eq!(service_key_name, "service_key");
        assert_eq!(*attr.get_domain_ref(), AttrDomain::Endpoint);
        assert_eq!(attr.zpl_value(), "endpoint.tag");
        assert_eq!(attr.get_values(), None);
        assert_eq!(attr.is_multi_valued(), false);
        assert_eq!(attr.is_tag(), true);
        assert_eq!(attr.optional, false);
    }

    #[test]
    fn test_parse_attribute_mapping_multi_valued() {
        let mapping = "service_key -> user.groups{}";
        let result = parse_attribute_mapping(mapping);

        assert!(result.is_ok());
        let (service_key_name, attr) = result.unwrap();

        assert_eq!(service_key_name, "service_key");
        assert_eq!(*attr.get_domain_ref(), AttrDomain::User);
        assert_eq!(attr.zpl_key(), "user.groups");
        assert_eq!(attr.get_values(), None);
        assert_eq!(attr.is_multi_valued(), true);
        assert_eq!(attr.is_tag(), false);
        assert_eq!(attr.optional, false);
    }

    #[test]
    fn test_parse_attribute_mapping_single_valued() {
        let mapping = "service_key -> service.role";
        let result = parse_attribute_mapping(mapping);

        assert!(result.is_ok());
        let (service_key_name, attr) = result.unwrap();

        assert_eq!(service_key_name, "service_key");
        assert_eq!(*attr.get_domain_ref(), AttrDomain::Service);
        assert_eq!(attr.zpl_key(), "service.role");
        assert_eq!(attr.get_values(), None);
        assert_eq!(attr.is_multi_valued(), false);
        assert_eq!(attr.is_tag(), false);
        assert_eq!(attr.optional, false);
    }

    #[test]
    fn test_parse_attribute_mapping_invalid_format() {
        let mapping = "invalid_format";
        let result = parse_attribute_mapping(mapping);

        assert!(result.is_err());
        if let Err(CompilationError::ConfigError(msg)) = result {
            assert!(msg.contains("invalid attribute mapping"));
            assert!(msg.contains("must be of the form"));
        } else {
            panic!("Expected ConfigError");
        }
    }

    #[test]
    fn test_parse_attribute_mapping_whitespace_handling() {
        let mapping = "  service_key  ->  user.name  ";
        let result = parse_attribute_mapping(mapping);

        assert!(result.is_ok());
        let (service_key_name, attr) = result.unwrap();

        assert_eq!(service_key_name, "service_key");
        assert_eq!(*attr.get_domain_ref(), AttrDomain::User);
        assert_eq!(attr.zpl_key(), "user.name");
        assert_eq!(attr.get_values(), None);
        assert_eq!(attr.is_multi_valued(), false);
        assert_eq!(attr.is_tag(), false);
        assert_eq!(attr.optional, false);
    }

    #[test]
    fn test_parse_attribute_mapping_too_many_arrows() {
        let mapping = "key -> attr -> extra";
        let result = parse_attribute_mapping(mapping);

        assert!(result.is_err());
        if let Err(CompilationError::ConfigError(msg)) = result {
            assert!(msg.contains("invalid attribute mapping"));
        } else {
            panic!("Expected ConfigError");
        }
    }
}
