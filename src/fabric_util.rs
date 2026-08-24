use std::collections::BTreeMap;

use crate::errors::CompilationError;
use crate::ptypes::FPos;
use zpr::policy_types::{AttrDomain, Attribute};

/// Prefix that marks an attribute key in the configuration description as a tag rather
/// than a key/value tuple. Matches the spelling used by `returns_attributes`.
pub const TAG_PREFIX: &str = "#";

/// Convert the list of (key, value) pairs into a list of attributes.
///
/// Note this only supports KEY:VALUE attributes, not TAG attributes.
///
/// TODO: This should be done in config parsing.
pub fn vec_to_attributes(v: &[(String, String)]) -> Result<Vec<Attribute>, CompilationError> {
    let mut attrs = Vec::new();
    for (k, v) in v {
        // `zpr.addr` lives in the ZPR-internal domain, which parse_domain rejects.
        // Route it through the internal constructor so it can appear in a provider clause.
        // This is currently how we assign a static address to a service.
        // Will need to be rethought in the future - see https://github.com/org-zpr/zpr-compiler/issues/133
        let attr = if k == crate::zpl::KATTR_ADDR {
            Attribute::try_zpr_internal_attr(k, v)?
        } else {
            Attribute::tuple(k).single().value(v).build()?
        };
        attrs.push(attr);
    }
    Ok(attrs)
}

/// Just like [vec_to_attributes] but also adds a domain hint to the attributes, and
/// understands the tag encoding used by the configuration description.
///
/// A key carrying the `#` prefix denotes a **tag** rather than a key/value tuple, the
/// same spelling `returns_attributes` uses for trusted services (`"role -> #user.admin"`).
/// A tag has no value, so `("#secure", "")` becomes the tag attribute `link.zpr.tag.secure`
/// while `("location", "usa")` becomes the tuple attribute `link.location` with value `usa`.
///
/// This matters because ZPL writes tags and key/value pairs with the same syntax
/// (`over secure, location:usa links`): without a tag-capable encoding on the
/// configuration side a ZPL tag condition could never be satisfied by a configured link.
pub fn vec_to_attributes_in_domain(
    v: &[(String, String)],
    domain: AttrDomain,
) -> Result<Vec<Attribute>, CompilationError> {
    let mut attrs = Vec::new();
    for (k, v) in v {
        let attr = if let Some(tag_name) = k.strip_prefix(TAG_PREFIX) {
            if !v.is_empty() {
                return Err(CompilationError::ConfigError(format!(
                    "tag attribute '{k}' must not have a value (got '{v}')",
                )));
            }
            Attribute::tag(tag_name).domain_hint(domain).build()?
        } else {
            Attribute::tuple(k)
                .domain_hint(domain)
                .single()
                .value(v)
                .build()?
        };
        attrs.push(attr);
    }
    Ok(attrs)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_zpr_addr_allowed_but_other_internal_rejected() {
        // zpr.addr is permitted and lands in the ZPR-internal domain.
        let ok = vec_to_attributes(&[("zpr.addr".to_string(), "fd5a:5052:8888::9".to_string())])
            .expect("zpr.addr should be allowed");
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].zpl_key(), "zpr.addr");

        // Other zpr.* keys still fail the domain check (no spoofing internal attrs).
        assert!(vec_to_attributes(&[("zpr.role".to_string(), "node".to_string())]).is_err());
    }

    #[test]
    fn test_config_tag_encoding_matches_zpl_tag_encoding() {
        // A "#name" key in the config is a tag and must encode to the same key ZPL
        // produces for `over name links`, otherwise no configured link could ever
        // satisfy a ZPL tag condition.
        let attrs = vec_to_attributes_in_domain(
            &[
                ("#secure".to_string(), "".to_string()),
                ("location".to_string(), "usa".to_string()),
            ],
            AttrDomain::Link,
        )
        .expect("link attributes should encode");

        assert_eq!(attrs.len(), 2);
        assert!(attrs[0].is_tag());
        assert_eq!(attrs[0].zpl_key(), "link.zpr.tag.secure");
        assert!(attrs[0].zpl_values().is_empty());

        assert!(!attrs[1].is_tag());
        assert_eq!(attrs[1].zpl_key(), "link.location");
        assert_eq!(attrs[1].zpl_value(), "usa");
    }

    #[test]
    fn test_config_tag_with_value_is_rejected() {
        // A tag is valueless by definition; silently dropping the value would hide a
        // config mistake.
        let err = vec_to_attributes_in_domain(
            &[("#secure".to_string(), "yes".to_string())],
            AttrDomain::Link,
        )
        .expect_err("tag carrying a value must be rejected");
        assert!(
            err.to_string().contains("must not have a value"),
            "unexpected error: {err}"
        );
    }
}

/// Given a list of attributes that apply, return just the set of unique
/// attributes and the ones with values should take precedence over ones without.
/// Keys are unique per tag (`<domain>.zpr.tag.<name>`), so tags never collide
/// with each other here; a BTreeMap keeps iteration deterministic.
pub fn squash_attributes(
    attrs: &[Attribute],
    tok: &FPos,
) -> Result<BTreeMap<String, Attribute>, CompilationError> {
    let mut attr_map: BTreeMap<String, Attribute> = BTreeMap::new();
    for a in attrs {
        if attr_map.contains_key(&a.zpl_key()) {
            // Map already has this attribute in it. If the map one has a value
            // and this one doesn't, keep the map one. If they both have values and they are different
            // that is an error.

            let map_attr = attr_map.get(&a.zpl_key()).unwrap();
            if map_attr.get_values().is_none() && a.get_values().is_some() {
                attr_map.insert(a.zpl_key(), a.clone()); // overwrite old non-valued attribute
            } else if map_attr.get_values().is_some() && a.get_values().is_none() {
                // do nothing
            } else if map_attr.get_values().is_some()
                && a.get_values().is_some()
                && map_attr.zpl_value() != a.zpl_value()
            {
                return Err(CompilationError::AttributeValueConflict(
                    a.zpl_key(),
                    tok.line,
                    tok.col,
                ));
            }
        } else {
            attr_map.insert(a.zpl_key(), a.clone());
        }
    }
    Ok(attr_map)
}
