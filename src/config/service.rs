//! Parser for the `services` TOML section, referencing defined protocols with optional overrides.

use std::collections::HashMap;

use toml::Table;

use crate::context::CompilationCtx;
use crate::err_config;
use crate::errors::CompilationError;
use crate::protocols::Protocol;

use super::protocol::{parse_icmp_details, parse_tcp_udp_ports};
use super::{ProtocolRefinement, Service, parse_provider};

fn warn_unknown_services_property(s: &Table, ctx: &CompilationCtx) -> Result<(), CompilationError> {
    for elem in s.keys() {
        match elem.as_str() {
            "protocol" => (),
            "icmp_type" => (),
            "icmp_codes" => (),
            "port" => (),
            "provider" => (),
            _ => ctx.warn(&format!(
                "unknown property '{elem}' detected while parsing services",
            ))?,
        }
    }
    Ok(())
}

/// Parse the very bare bones individual service table.
///
/// A service must reference a defined protocol using the `protocol` key, it can also
/// additionally override a port or icmp setting in a defined protocol.
pub(super) fn parse_service(
    sid: &str,
    s: &Table,
    protocols: &HashMap<String, Protocol>,
    ctx: &CompilationCtx,
) -> Result<Service, CompilationError> {
    warn_unknown_services_property(s, ctx)?;
    if !s.contains_key("protocol") {
        return Err(err_config!("service {} missing protocol", sid));
    }
    let protocol_label = s["protocol"]
        .as_str()
        .ok_or(err_config!("service {} missing protocol", sid))?
        .to_string();
    let provider = if s.contains_key("provider") {
        Some(parse_provider(&format!("service {}", sid), s)?)
    } else {
        None
    };

    let Some(matched_protocol) = protocols.get(&protocol_label) else {
        return Err(err_config!(
            "service {} references unknown protocol {}",
            sid,
            protocol_label
        ));
    };

    // The service could contain overrides for protocol.
    let opt_refine = if matched_protocol.is_icmp() {
        if s.contains_key("icmp_type") || s.contains_key("icmp_codes") {
            Some(ProtocolRefinement::Icmp(parse_icmp_details(sid, s)?))
        } else {
            None
        }
    } else if s.contains_key("port") {
        Some(ProtocolRefinement::Port(parse_tcp_udp_ports(sid, s)?))
    } else {
        None
    };

    Ok(Service {
        id: sid.to_string(),
        protocol_id: protocol_label,
        protocol_refinement: opt_refine,
        provider,
    })
}
