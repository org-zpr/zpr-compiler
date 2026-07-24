//! Parser for the `trusted_services` TOML section and its attribute-mapping syntax.

use std::collections::HashSet;
use std::path::PathBuf;

use toml::Table;
use zpr::policy_types::{AttrMapping, parse_attribute_mapping};

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
            "expiration_seconds" => (),
            _ => ctx.warn(&format!(
                "unknown property '{elem}' detected while parsing trusted_services",
            ))?,
        }
    }
    Ok(())
}

/// Validate a trusted-service TOML id. It must match `[A-Za-z0-9_-]+` so it can be used
/// unchanged as both a policy `Service.id` and the `<serviceId>.json` filename stem.
pub(super) fn validate_ts_id(ts_id: &str) -> Result<(), CompilationError> {
    if ts_id.is_empty()
        || !ts_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(err_config!(
            "trusted_service id '{}' is invalid; must match [A-Za-z0-9_-]+",
            ts_id
        ));
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

/// Parse the `expiration_seconds` property: default `0`, must be a non-negative TOML integer
/// that fits in `u32`. Rejected outright on the builtin `default` service.
fn parse_expiration_seconds(
    ts: &Table,
    ts_id: &str,
    is_default: bool,
) -> Result<u32, CompilationError> {
    if !ts.contains_key("expiration_seconds") {
        return Ok(0);
    }
    if is_default {
        return Err(err_config!(
            "default trusted_service does not allow expiration_seconds"
        ));
    }
    // `as_integer` rejects strings, floats, and booleans.
    let v = ts["expiration_seconds"].as_integer().ok_or(err_config!(
        "trusted_service {} expiration_seconds must be a non-negative integer",
        ts_id
    ))?;
    if v < 0 {
        return Err(err_config!(
            "trusted_service {} expiration_seconds must be non-negative",
            ts_id
        ));
    }
    u32::try_from(v).map_err(|_| {
        err_config!(
            "trusted_service {} expiration_seconds {} exceeds u32 range",
            ts_id,
            v
        )
    })
}

/// Parse each `"<service-key> -> <attr-spec>"` string into an ordered `Vec<AttrMapping>`,
/// rejecting duplicate service keys via a temporary set (no parallel map retained).
fn parse_return_mappings(
    ts_id: &str,
    raw: &[String],
) -> Result<Vec<AttrMapping>, CompilationError> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for ra in raw {
        let m = parse_attribute_mapping(ra)
            .map_err(|e| err_config!("trusted_service {}: {}", ts_id, e))?;
        if !seen.insert(m.service_attr_key.clone()) {
            return Err(err_config!(
                "trusted_service {} contains duplicate service attribute name '{}'",
                ts_id,
                m.service_attr_key
            ));
        }
        out.push(m);
    }
    Ok(out)
}

/// A `file` service has no network presence: no provider, client/service interfaces, or cert.
/// It only declares `returns_attributes` (>= 1 mapping) and optional `expiration_seconds`.
fn parse_file_trusted_service(
    ts_id: &str,
    ts: &Table,
    expiration_seconds: u32,
) -> Result<TrustedService, CompilationError> {
    for forbidden in [
        "identity_attributes",
        "provider",
        "client",
        "service",
        "cert_path",
        "prefix",
    ] {
        if ts.contains_key(forbidden) {
            return Err(err_config!(
                "trusted_service {} with api \"file\" does not allow property '{}'",
                ts_id,
                forbidden
            ));
        }
    }
    if !ts.contains_key("returns_attributes") {
        return Err(err_config!(
            "trusted_service {} with api \"file\" requires returns_attributes",
            ts_id
        ));
    }
    let raw = parse_string_array(ts, "returns_attributes", "trusted_service")?;
    let returns_attrs = parse_return_mappings(ts_id, &raw)?;
    if returns_attrs.is_empty() {
        return Err(err_config!(
            "trusted_service {} with api \"file\" requires at least one returns_attributes mapping",
            ts_id
        ));
    }
    Ok(TrustedService {
        id: ts_id.to_string(),
        api: zpl::TS_API_FILE.to_string(),
        expiration_seconds: expiration_seconds,
        returns_attrs: returns_attrs,
        ..Default::default()
    })
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

    let expiration_seconds = parse_expiration_seconds(ts, ts_id, is_default)?;

    if api == zpl::TS_API_FILE {
        if is_default {
            return Err(err_config!(
                "default trusted_service cannot have api \"file\""
            ));
        }
        return parse_file_trusted_service(ts_id, ts, expiration_seconds);
    }

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

    let returns_raw: Vec<String>;
    let identity_raw: Vec<String>;
    let client_svc: Option<String>;
    let service_svc: Option<String>;
    if !is_default {
        returns_raw = parse_string_array(ts, "returns_attributes", "trusted_service")?;
        identity_raw = parse_string_array(ts, "identity_attributes", "trusted_service")?;

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
        returns_raw = vec![format!("{} -> {}", zpl::KATTR_CN, zpl::KATTR_CN)];
        identity_raw = vec![String::from(zpl::KATTR_CN)];
        client_svc = None;
        service_svc = None;
    }

    let returns_attrs = parse_return_mappings(ts_id, &returns_raw)?;

    let mut identity_attrs = Vec::new();
    for ra in &identity_raw {
        // The ident attribute (for now) must exist in the returns attributes.
        if !returns_attrs.iter().any(|m| &m.service_attr_key == ra) {
            return Err(err_config!(
                "trusted_service {} identity attribute '{}' not in returns_attributes",
                ts_id,
                ra
            ));
        }
        identity_attrs.push(ra.to_string());
    }

    let provider = if ts.contains_key("provider") {
        Some(parse_provider(&format!("trusted_service {ts_id}"), ts)?)
    } else if !is_default {
        return Err(err_config!("trusted_service {} missing provider", ts_id));
    } else {
        None
    };

    Ok(TrustedService {
        id: ts_id.to_string(),
        api,
        expiration_seconds,
        cert_path,
        returns_attrs,
        identity_attrs,
        provider,
        client: client_svc,
        service: service_svc,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    fn body(s: &str) -> Table {
        s.parse::<Table>().unwrap()
    }

    fn find<'a>(ts: &'a TrustedService, key: &str) -> &'a AttrMapping {
        ts.returns_attrs
            .iter()
            .find(|m| m.service_attr_key == key)
            .unwrap()
    }

    #[test]
    fn test_file_service_ordered_mappings_default_expiration() {
        let t = body(
            r#"
            api = "file"
            returns_attributes = ["color -> user.color", "hair -> #device.tag", "groups -> user.groups{}"]
            "#,
        );
        let ts = parse_trusted_service("attrfile", &t, &CompilationCtx::default()).unwrap();
        assert_eq!(ts.api, zpl::TS_API_FILE);
        assert_eq!(ts.expiration_seconds, 0);
        assert!(ts.identity_attrs.is_empty());
        assert!(ts.provider.is_none());
        // declaration order preserved with exact trimmed RHS spelling
        let keys: Vec<&str> = ts
            .returns_attrs
            .iter()
            .map(|m| m.service_attr_key.as_str())
            .collect();
        assert_eq!(keys, vec!["color", "hair", "groups"]);
        assert_eq!(find(&ts, "hair").zpr_attr_spec, "#device.tag");
        assert_eq!(find(&ts, "groups").zpr_attr_spec, "user.groups{}");
    }

    #[test]
    fn test_file_service_positive_expiration() {
        let t = body(
            r#"
            api = "file"
            expiration_seconds = 3600
            returns_attributes = ["color -> user.color"]
            "#,
        );
        let ts = parse_trusted_service("attrfile", &t, &CompilationCtx::default()).unwrap();
        assert_eq!(ts.expiration_seconds, 3600);
    }

    #[test]
    fn test_expiration_negative_rejected() {
        let t = body(
            r#"
            api = "file"
            expiration_seconds = -1
            returns_attributes = ["color -> user.color"]
            "#,
        );
        let err = parse_trusted_service("attrfile", &t, &CompilationCtx::default()).unwrap_err();
        assert!(err.to_string().contains("non-negative"), "{err}");
    }

    #[test]
    fn test_expiration_overflow_rejected() {
        let t = body(
            r#"
            api = "file"
            expiration_seconds = 4294967296
            returns_attributes = ["color -> user.color"]
            "#,
        );
        let err = parse_trusted_service("attrfile", &t, &CompilationCtx::default()).unwrap_err();
        assert!(err.to_string().contains("exceeds u32"), "{err}");
    }

    #[test]
    fn test_expiration_wrong_types_rejected() {
        for val in ["\"3600\"", "3.5", "true"] {
            let t = body(&format!(
                "api = \"file\"\nexpiration_seconds = {val}\nreturns_attributes = [\"color -> user.color\"]\n"
            ));
            let err =
                parse_trusted_service("attrfile", &t, &CompilationCtx::default()).unwrap_err();
            assert!(
                err.to_string().contains("must be a non-negative integer"),
                "value {val} gave: {err}"
            );
        }
    }

    #[test]
    fn test_file_forbidden_properties_rejected() {
        for (prop, line) in [
            ("identity_attributes", "identity_attributes = [\"color\"]"),
            ("provider", "provider = [[\"foo\", \"bar\"]]"),
            ("client", "client = \"c\""),
            ("service", "service = \"s\""),
            ("cert_path", "cert_path = \"x.pem\""),
            ("prefix", "prefix = \"bar.hop\""),
        ] {
            let t = body(&format!(
                "api = \"file\"\nreturns_attributes = [\"color -> user.color\"]\n{line}\n"
            ));
            let err =
                parse_trusted_service("attrfile", &t, &CompilationCtx::default()).unwrap_err();
            assert!(
                err.to_string().contains(prop) && err.to_string().contains("does not allow"),
                "property {prop} gave: {err}"
            );
        }
    }

    #[test]
    fn test_file_requires_returns_attributes() {
        let t = body("api = \"file\"\n");
        let err = parse_trusted_service("attrfile", &t, &CompilationCtx::default()).unwrap_err();
        assert!(
            err.to_string().contains("requires returns_attributes"),
            "{err}"
        );

        let t = body("api = \"file\"\nreturns_attributes = []\n");
        let err = parse_trusted_service("attrfile", &t, &CompilationCtx::default()).unwrap_err();
        assert!(err.to_string().contains("at least one"), "{err}");
    }

    #[test]
    fn test_file_duplicate_service_key_rejected() {
        let t = body(
            r#"
            api = "file"
            returns_attributes = ["color -> user.color", "color -> #device.tag"]
            "#,
        );
        let err = parse_trusted_service("attrfile", &t, &CompilationCtx::default()).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn test_expiration_on_default_rejected() {
        // id "default" with no api => builtin default; expiration is not allowed.
        let t = body("expiration_seconds = 10\ncert_path = \"foo.pem\"\n");
        let err = parse_trusted_service("default", &t, &CompilationCtx::default()).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not allow expiration_seconds"),
            "{err}"
        );
    }

    #[test]
    fn test_validate_ts_id() {
        assert!(validate_ts_id("attrfile").is_ok());
        assert!(validate_ts_id("bas-1_2").is_ok());
        for bad in ["", "bad id", "a/b", "..", "café", "a.b"] {
            assert!(
                validate_ts_id(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }
}
