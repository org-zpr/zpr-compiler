//! Parser for the `trusted_services` TOML section and its attribute-mapping syntax.

use std::collections::HashSet;
use std::path::PathBuf;

use toml::Table;
use zpr::policy_types::{AttrMapping, parse_attribute_mapping};

use crate::context::CompilationCtx;
use crate::err_config;
use crate::errors::CompilationError;
use crate::zpl;

use super::{OidcTsConfig, TrustedService, parse_provider};

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
            // api = "oidc" properties
            "issuer" => (),
            "jwks_uri" => (),
            "client_id" => (),
            "client_secret" => (),
            "scopes" => (),
            "allowed_domains" => (),
            "seed_jwks" => (),
            "max_auth_age_seconds" => (),
            "allow_offline_access" => (),
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
///
/// ZPR owns the `zpr.` sub-namespace inside every class domain
/// (`device.zpr.adapter.cn`, `user.zpr.tag.red`, `user.zpr.authority`). Only the
/// default trusted service vouches for those keys; a declared service claiming
/// one could forge an identity key or, since #144, an authentication marker.
/// `is_default` exempts the builtin default service's own mappings.
fn parse_return_mappings(
    ts_id: &str,
    raw: &[String],
    is_default: bool,
) -> Result<Vec<AttrMapping>, CompilationError> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for ra in raw {
        let m = parse_attribute_mapping(ra)
            .map_err(|e| err_config!("trusted_service {}: {}", ts_id, e))?;
        let name = m.attr.get_name();
        if !is_default && (name == "zpr" || name.starts_with("zpr.")) {
            return Err(err_config!(
                "trusted_service {}: attribute '{}' is reserved for ZPR",
                ts_id,
                m.zpr_attr_spec
            ));
        }
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
    // A `file` service is never the builtin default (`api = "file"` on the
    // default id is rejected upstream), so reserved-namespace checks apply.
    let returns_attrs = parse_return_mappings(ts_id, &raw, false)?;
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

/// An `api = "oidc"` trusted service declares an off-net OpenID Connect
/// identity provider (see spec-OIDC.md "ZPLC configuration"). The adapter is
/// the Relying Party, so `client` is not allowed; the provider is off-net, so
/// `provider` and `cert_path` are not allowed either (TLS to the provider is
/// verified against system roots). Each validation rule below has a dedicated
/// unit test; the error text is the contract.
fn parse_oidc_trusted_service(
    ts_id: &str,
    ts: &Table,
    expiration_seconds: u32,
    ctx: &CompilationCtx,
) -> Result<TrustedService, CompilationError> {
    // Properties that make no sense for an off-net OIDC provider.
    if ts.contains_key("client") {
        return Err(err_config!(
            "trusted_service {}: \"client\" is not allowed for api=\"oidc\" (the adapter talks to the provider directly)",
            ts_id
        ));
    }
    if ts.contains_key("provider") {
        return Err(err_config!(
            "trusted_service {}: \"provider\" is not allowed for api=\"oidc\"",
            ts_id
        ));
    }
    if ts.contains_key("cert_path") {
        return Err(err_config!(
            "trusted_service {}: \"cert_path\" is not allowed for api=\"oidc\" (TLS to the provider is verified against system roots)",
            ts_id
        ));
    }
    if ts.contains_key("prefix") {
        return Err(err_config!(
            "trusted_service {} with api \"oidc\" does not allow property 'prefix'",
            ts_id
        ));
    }

    // issuer: required https URL without query or fragment.
    let issuer = ts
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if !issuer.starts_with("https://") || issuer.contains('?') || issuer.contains('#') {
        return Err(err_config!(
            "trusted_service {}: issuer must be an https URL without query or fragment",
            ts_id
        ));
    }

    // jwks_uri: required https URL.
    let jwks_uri = ts
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if !jwks_uri.starts_with("https://") {
        return Err(err_config!(
            "trusted_service {}: jwks_uri is required and must be https",
            ts_id
        ));
    }

    // client_id: required, non-empty.
    let client_id = ts
        .get("client_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if client_id.is_empty() {
        return Err(err_config!(
            "trusted_service {}: client_id is required",
            ts_id
        ));
    }

    // client_secret: optional string (a public, non-secret value for native apps).
    let client_secret = match ts.get("client_secret") {
        None => None,
        Some(v) => Some(
            v.as_str()
                .ok_or(err_config!(
                    "trusted_service {} client_secret is not a string",
                    ts_id
                ))?
                .to_string(),
        ),
    };

    // scopes: optional, defaults to the standard OIDC triple; must contain "openid".
    let scopes = if ts.contains_key("scopes") {
        parse_string_array(ts, "scopes", "trusted_service")?
    } else {
        vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ]
    };
    if !scopes.iter().any(|s| s == "openid") {
        return Err(err_config!(
            "trusted_service {}: scopes must include \"openid\"",
            ts_id
        ));
    }

    // allowed_domains: required, non-empty. ["*"] means any account.
    let allowed_domains = parse_string_array(ts, "allowed_domains", "trusted_service")?;
    if allowed_domains.is_empty() {
        return Err(err_config!(
            "trusted_service {}: allowed_domains is required (use [\"*\"] to accept any account)",
            ts_id
        ));
    }

    // seed_jwks: optional path, captured verbatim. It is resolved relative to
    // the .zplc and existence-checked when the key set is embedded (B2).
    let seed_jwks_path = match ts.get("seed_jwks") {
        None => None,
        Some(v) => Some(PathBuf::from(v.as_str().ok_or(err_config!(
            "trusted_service {} seed_jwks is not a string",
            ts_id
        ))?)),
    };

    // expiration_seconds: parsed by the caller; must be positive for oidc so
    // issued credentials always have a policy-declared lifetime.
    if expiration_seconds == 0 {
        return Err(err_config!(
            "trusted_service {}: expiration_seconds is required for api=\"oidc\"",
            ts_id
        ));
    }

    // max_auth_age_seconds: optional u32, default 0 (no freshness requirement).
    let max_auth_age_seconds = if ts.contains_key("max_auth_age_seconds") {
        let v = ts["max_auth_age_seconds"].as_integer().ok_or(err_config!(
            "trusted_service {} max_auth_age_seconds must be a non-negative integer",
            ts_id
        ))?;
        u32::try_from(v).map_err(|_| {
            err_config!(
                "trusted_service {} max_auth_age_seconds must be a non-negative integer that fits in u32",
                ts_id
            )
        })?
    } else {
        0
    };

    // allow_offline_access: optional bool, default false.
    let allow_offline_access = match ts.get("allow_offline_access") {
        None => false,
        Some(v) => v.as_bool().ok_or(err_config!(
            "trusted_service {} allow_offline_access must be a boolean",
            ts_id
        ))?,
    };

    // returns_attributes: required, >= 1 mapping; the reserved-namespace check
    // in parse_return_mappings applies (an oidc service is never the default).
    let returns_raw = parse_string_array(ts, "returns_attributes", "trusted_service")?;
    let returns_attrs = parse_return_mappings(ts_id, &returns_raw, false)?;
    if returns_attrs.is_empty() {
        return Err(err_config!(
            "trusted_service {} with api \"oidc\" requires at least one returns_attributes mapping",
            ts_id
        ));
    }

    // identity_attributes: required, must be exactly ["sub"]. The OIDC `sub`
    // claim is the only stable identifier; email addresses are mutable and
    // reusable, so "email" gets a dedicated message.
    let identity_raw = parse_string_array(ts, "identity_attributes", "trusted_service")?;
    if identity_raw.iter().any(|a| a == "email") {
        return Err(err_config!(
            "trusted_service {}: \"email\" cannot be an identity attribute: addresses are mutable and reusable; use \"sub\"",
            ts_id
        ));
    }
    if identity_raw != vec!["sub".to_string()] {
        return Err(err_config!(
            "trusted_service {}: identity_attributes must be [\"sub\"]",
            ts_id
        ));
    }
    // As for other apis, an identity attribute must be a returned service key.
    if !returns_attrs.iter().any(|m| m.service_attr_key == "sub") {
        return Err(err_config!(
            "trusted_service {} identity attribute 'sub' not in returns_attributes",
            ts_id
        ));
    }

    // service: optional. When omitted the visa service has no on-net path to
    // the provider and will need direct internet egress to reach jwks_uri.
    let service_svc = match ts.get("service") {
        None => {
            ctx.warn(&format!(
                "trusted_service {ts_id}: no \"service\" declared; the visa service will need direct internet egress to reach jwks_uri"
            ))?;
            None
        }
        Some(v) => Some(
            v.as_str()
                .ok_or(err_config!("trusted_service {} service parse error", ts_id))?
                .to_string(),
        ),
    };

    Ok(TrustedService {
        id: ts_id.to_string(),
        api: zpl::TS_API_OIDC.to_string(),
        expiration_seconds,
        service: service_svc,
        returns_attrs,
        identity_attrs: vec!["sub".to_string()],
        oidc: Some(OidcTsConfig {
            issuer,
            jwks_uri,
            client_id,
            client_secret,
            scopes,
            allowed_domains,
            seed_jwks_path,
            max_auth_age_seconds,
            allow_offline_access,
        }),
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

    if api == zpl::TS_API_OIDC {
        // Guard on the id: `is_default` is only set when `api` is omitted,
        // but the builtin default service must never be an OIDC provider.
        if is_default || ts_id == zpl::DEFAULT_TRUSTED_SERVICE_ID {
            return Err(err_config!(
                "default trusted_service cannot have api \"oidc\""
            ));
        }
        return parse_oidc_trusted_service(ts_id, ts, expiration_seconds, ctx);
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

    let returns_attrs = parse_return_mappings(ts_id, &returns_raw, is_default)?;

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
        oidc: None,
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

    // A declared (non-default) trusted service must not claim any attribute in
    // the ZPR-owned `zpr.` sub-namespace of a class domain: doing so could
    // forge an identity key (`device.zpr.adapter.cn`) or an authority marker
    // (`user.zpr.authority`, issue #144 / PR #145 review).
    #[test]
    fn test_reserved_zpr_namespace_rejected_for_declared_service() {
        for spec in [
            "user.zpr.authority",
            "device.zpr.authority",
            "device.zpr.adapter.cn",
            "user.zpr.authority{}",
            "user.zpr",
        ] {
            let t = body(&format!(
                "api = \"file\"\nreturns_attributes = [\"foo -> {spec}\"]\n"
            ));
            let err =
                parse_trusted_service("attrfile", &t, &CompilationCtx::default()).unwrap_err();
            assert!(
                err.to_string().contains("reserved for ZPR"),
                "spec {spec} gave: {err}"
            );
        }
    }

    // The tag form `#user.zprish` is the normal tag mechanism: it encodes to
    // `user.zpr.tag.zprish`, which never collides with a reserved tuple key,
    // so tags with ordinary names stay accepted -- as do non-`zpr.` tuple
    // names and names merely containing "zpr".
    #[test]
    fn test_reserved_zpr_namespace_scope() {
        for spec in [
            "user.zprish",
            "user.authority",
            "device.myzpr.x",
            "#user.zprish",
        ] {
            let t = body(&format!(
                "api = \"file\"\nreturns_attributes = [\"foo -> {spec}\"]\n"
            ));
            assert!(
                parse_trusted_service("attrfile", &t, &CompilationCtx::default()).is_ok(),
                "spec {spec} should be accepted"
            );
        }
    }

    // The builtin default trusted service's own `device.zpr.adapter.cn`
    // mapping must still parse: the reservation applies to declared services
    // only.
    #[test]
    fn test_default_service_keeps_reserved_cn_mapping() {
        let t = body("cert_path = \"foo.pem\"\n");
        let ts = parse_trusted_service("default", &t, &CompilationCtx::default()).unwrap();
        assert_eq!(ts.returns_attrs.len(), 1);
        assert_eq!(ts.returns_attrs[0].service_attr_key, zpl::KATTR_CN);
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

    // ----- api = "oidc" (issue #148) -----

    /// A minimal valid oidc declaration: only the required properties.
    fn oidc_minimal() -> String {
        r#"
            api = "oidc"
            issuer = "https://accounts.google.com"
            jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
            client_id = "my-client-id.apps.googleusercontent.com"
            allowed_domains = ["example.com"]
            expiration_seconds = 3600
            service = "google-jwks"
            returns_attributes = ["sub -> user.sub", "email -> user.email"]
            identity_attributes = ["sub"]
        "#
        .to_string()
    }

    /// Parse a minimal declaration with one line replaced (or dropped when
    /// `replacement` is empty). `needle` must match a whole property line.
    fn oidc_with(needle: &str, replacement: &str) -> Table {
        let src = oidc_minimal();
        let line = src
            .lines()
            .find(|l| l.trim_start().starts_with(needle))
            .unwrap_or_else(|| panic!("no line starting with {needle}"));
        body(&src.replace(line.trim(), replacement))
    }

    #[test]
    fn test_oidc_minimal_valid() {
        let ts =
            parse_trusted_service("google", &body(&oidc_minimal()), &CompilationCtx::default())
                .unwrap();
        assert_eq!(ts.api, zpl::TS_API_OIDC);
        assert_eq!(ts.expiration_seconds, 3600);
        assert_eq!(ts.service.as_deref(), Some("google-jwks"));
        assert!(ts.client.is_none());
        assert!(ts.cert_path.is_none());
        assert!(ts.provider.is_none());
        assert_eq!(ts.identity_attrs, vec!["sub"]);
        let keys: Vec<&str> = ts
            .returns_attrs
            .iter()
            .map(|m| m.service_attr_key.as_str())
            .collect();
        assert_eq!(keys, vec!["sub", "email"]);
        let oidc = ts.oidc.expect("oidc config present");
        assert_eq!(oidc.issuer, "https://accounts.google.com");
        assert_eq!(oidc.jwks_uri, "https://www.googleapis.com/oauth2/v3/certs");
        assert_eq!(oidc.client_id, "my-client-id.apps.googleusercontent.com");
        assert_eq!(oidc.client_secret, None);
        // scopes default to the standard OIDC triple.
        assert_eq!(oidc.scopes, vec!["openid", "email", "profile"]);
        assert_eq!(oidc.allowed_domains, vec!["example.com"]);
        assert_eq!(oidc.seed_jwks_path, None);
        assert_eq!(oidc.max_auth_age_seconds, 0);
        assert!(!oidc.allow_offline_access);
    }

    #[test]
    fn test_oidc_optional_properties_captured() {
        let mut src = oidc_minimal();
        src.push_str(
            r#"
            client_secret = "not-actually-secret"
            scopes = ["openid", "email"]
            seed_jwks = "keys/google-jwks.json"
            max_auth_age_seconds = 86400
            allow_offline_access = true
        "#,
        );
        let ts = parse_trusted_service("google", &body(&src), &CompilationCtx::default()).unwrap();
        let oidc = ts.oidc.unwrap();
        assert_eq!(oidc.client_secret.as_deref(), Some("not-actually-secret"));
        assert_eq!(oidc.scopes, vec!["openid", "email"]);
        assert_eq!(
            oidc.seed_jwks_path,
            Some(PathBuf::from("keys/google-jwks.json"))
        );
        assert_eq!(oidc.max_auth_age_seconds, 86400);
        assert!(oidc.allow_offline_access);
    }

    #[test]
    fn test_oidc_issuer_rules() {
        for bad in [
            "",                                          // missing (dropped below)
            "issuer = \"http://accounts.google.com\"",   // not https
            "issuer = \"https://idp.example.com?x=1\"",  // query
            "issuer = \"https://idp.example.com#frag\"", // fragment
            "issuer = 42",                               // not a string
        ] {
            let t = oidc_with("issuer =", bad);
            let err = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap_err();
            assert_eq!(
                err.to_string(),
                "configuration error: trusted_service google: issuer must be an https URL without query or fragment",
                "case {bad:?}"
            );
        }
    }

    #[test]
    fn test_oidc_jwks_uri_rules() {
        for bad in ["", "jwks_uri = \"http://x.example.com/certs\""] {
            let t = oidc_with("jwks_uri =", bad);
            let err = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap_err();
            assert_eq!(
                err.to_string(),
                "configuration error: trusted_service google: jwks_uri is required and must be https",
                "case {bad:?}"
            );
        }
    }

    #[test]
    fn test_oidc_client_id_required() {
        for bad in ["", "client_id = \"\""] {
            let t = oidc_with("client_id =", bad);
            let err = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap_err();
            assert_eq!(
                err.to_string(),
                "configuration error: trusted_service google: client_id is required",
                "case {bad:?}"
            );
        }
    }

    #[test]
    fn test_oidc_scopes_must_include_openid() {
        let mut src = oidc_minimal();
        src.push_str("scopes = [\"email\", \"profile\"]\n");
        let err =
            parse_trusted_service("google", &body(&src), &CompilationCtx::default()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "configuration error: trusted_service google: scopes must include \"openid\""
        );
    }

    #[test]
    fn test_oidc_allowed_domains_required() {
        for bad in ["", "allowed_domains = []"] {
            let t = oidc_with("allowed_domains =", bad);
            let err = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap_err();
            assert_eq!(
                err.to_string(),
                "configuration error: trusted_service google: allowed_domains is required (use [\"*\"] to accept any account)",
                "case {bad:?}"
            );
        }
    }

    #[test]
    fn test_oidc_allowed_domains_wildcard_accepted() {
        let t = oidc_with("allowed_domains =", "allowed_domains = [\"*\"]");
        let ts = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap();
        assert_eq!(ts.oidc.unwrap().allowed_domains, vec!["*"]);
    }

    #[test]
    fn test_oidc_expiration_seconds_required_and_positive() {
        for bad in ["", "expiration_seconds = 0"] {
            let t = oidc_with("expiration_seconds =", bad);
            let err = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap_err();
            assert_eq!(
                err.to_string(),
                "configuration error: trusted_service google: expiration_seconds is required for api=\"oidc\"",
                "case {bad:?}"
            );
        }
    }

    #[test]
    fn test_oidc_returns_attributes_required() {
        let t = oidc_with("returns_attributes =", "");
        let err = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap_err();
        assert!(err.to_string().contains("at least one"), "{err}");
    }

    #[test]
    fn test_oidc_reserved_namespace_still_applies() {
        let t = oidc_with(
            "returns_attributes =",
            "returns_attributes = [\"sub -> user.zpr.authority\"]",
        );
        let err = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap_err();
        assert!(err.to_string().contains("reserved for ZPR"), "{err}");
    }

    #[test]
    fn test_oidc_identity_attributes_must_be_sub() {
        for bad in [
            "",
            "identity_attributes = []",
            "identity_attributes = [\"sub\", \"email\"]", // email has priority message
            "identity_attributes = [\"cn\"]",
        ] {
            let t = oidc_with("identity_attributes =", bad);
            let err = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("identity_attributes must be [\"sub\"]")
                    || msg.contains("cannot be an identity attribute"),
                "case {bad:?} gave: {msg}"
            );
        }
    }

    #[test]
    fn test_oidc_email_identity_attribute_dedicated_message() {
        let t = oidc_with("identity_attributes =", "identity_attributes = [\"email\"]");
        let err = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "configuration error: trusted_service google: \"email\" cannot be an identity attribute: addresses are mutable and reusable; use \"sub\""
        );
    }

    #[test]
    fn test_oidc_identity_sub_must_be_returned() {
        let t = oidc_with(
            "returns_attributes =",
            "returns_attributes = [\"email -> user.email\"]",
        );
        let err = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap_err();
        assert!(
            err.to_string().contains("'sub' not in returns_attributes"),
            "{err}"
        );
    }

    #[test]
    fn test_oidc_missing_service_warns() {
        let t = oidc_with("service =", "");
        // With werror the warning is promoted to an error we can assert on.
        let err =
            parse_trusted_service("google", &t, &CompilationCtx::new(false, true)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "warning: trusted_service google: no \"service\" declared; the visa service will need direct internet egress to reach jwks_uri"
        );
        // Without werror it parses, with no service recorded.
        let ts = parse_trusted_service("google", &t, &CompilationCtx::default()).unwrap();
        assert!(ts.service.is_none());
    }

    #[test]
    fn test_oidc_forbidden_properties_rejected() {
        for (line, expect) in [
            (
                "client = \"c\"",
                "\"client\" is not allowed for api=\"oidc\" (the adapter talks to the provider directly)",
            ),
            (
                "provider = [[\"foo\", \"bar\"]]",
                "\"provider\" is not allowed for api=\"oidc\"",
            ),
            (
                "cert_path = \"x.pem\"",
                "\"cert_path\" is not allowed for api=\"oidc\" (TLS to the provider is verified against system roots)",
            ),
            (
                "prefix = \"bar.hop\"",
                "with api \"oidc\" does not allow property 'prefix'",
            ),
        ] {
            let mut src = oidc_minimal();
            src.push_str(line);
            src.push('\n');
            let err = parse_trusted_service("google", &body(&src), &CompilationCtx::default())
                .unwrap_err();
            assert!(
                err.to_string().contains(expect),
                "property line {line:?} gave: {err}"
            );
        }
    }

    #[test]
    fn test_oidc_on_default_rejected() {
        let t = oidc_with("api =", "api = \"oidc\"");
        let err = parse_trusted_service("default", &t, &CompilationCtx::default()).unwrap_err();
        assert!(
            err.to_string()
                .contains("default trusted_service cannot have api \"oidc\""),
            "{err}"
        );
    }
}
