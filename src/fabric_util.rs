use std::collections::HashMap;

use crate::errors::CompilationError;
use crate::ptypes::FPos;
use zpr::policy_types::{AttrDomain, Attribute};

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

/// Just like [vec_to_attributes] but also adds a domain hint to the attributes.
pub fn vec_to_attributes_in_domain(
    v: &[(String, String)],
    domain: AttrDomain,
) -> Result<Vec<Attribute>, CompilationError> {
    let mut attrs = Vec::new();
    for (k, v) in v {
        attrs.push(
            Attribute::tuple(k)
                .domain_hint(domain)
                .single()
                .value(v)
                .build()?,
        );
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
}

/// Given a list of attributes that apply, return just the set of unique
/// attributes and the ones with values should take precedence over ones without.
pub fn squash_attributes(
    attrs: &[Attribute],
    tok: &FPos,
) -> Result<HashMap<String, Attribute>, CompilationError> {
    let mut attr_map: HashMap<String, Attribute> = HashMap::new();
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
