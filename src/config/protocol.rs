//! Parser for the `protocols` TOML section, covering TCP/UDP port specs and ICMP details.

use toml::Table;

use crate::context::CompilationCtx;
use crate::err_config;
use crate::errors::CompilationError;
use crate::protocols::{IanaProtocol, IcmpFlowType, PortSpec, Protocol};
use crate::zpl;

fn warn_unknown_prot_property(prot: &Table, ctx: &CompilationCtx) -> Result<(), CompilationError> {
    for elem in prot.keys() {
        match elem.as_str() {
            "l4protocol" => (),
            "port" => (),
            "icmp_type" => (),
            "icmp_codes" => (),
            "l7protocol" => (),
            "protocol" => (),
            _ => ctx.warn(&format!(
                "unknown property '{elem}' detected while parsing protocols",
            ))?,
        }
    }
    Ok(())
}

/// Convert a TOML integer to a u8.  Returns None if the integer is out of range.
fn toml_as_u8(v: &toml::Value) -> Option<u8> {
    match v {
        toml::Value::Integer(i) if *i >= 0 && *i <= 255 => Some(*i as u8),
        _ => None,
    }
}

/// Parse the "port" value, if not found or invalid return an error.
/// Valid port format is:
/// - single port number, eg `port = 80`
/// - comma separated list of port numbers, eg `port = "22,80,443"`
/// - range of port numbers, eg `port = "8000-9000"`
/// - comma separated mix of the above (eg, `port = "22,80,443,8000-9000"`)
pub(super) fn parse_tcp_udp_ports(
    ctx: &str,
    tab: &Table,
) -> Result<Vec<PortSpec>, CompilationError> {
    let ps_strv = if tab.contains_key("port") {
        if tab["port"].is_str() {
            tab["port"].as_str().unwrap().to_string()
        } else {
            tab["port"].to_string()
        }
    } else {
        return Err(err_config!("protocol {} missing port", ctx));
    };

    // Valid form of `ps_strv` is:
    // - single port number
    // - comma separated list of port numbers
    // - range of port numbers (e.g. 8000-9000)
    // - comma separated mix of the above (e.g. 22,80,443,8000-9000)
    PortSpec::parse_list(&ps_strv).map_err(|e| {
        err_config!(
            "protocol {} invalid port specification '{}': {}",
            ctx,
            ps_strv,
            e
        )
    })
}

/// Parse and do light error checking on the ICMP details (the icmp_type and icmp_codes).
pub(super) fn parse_icmp_details(
    prot_id: &str,
    prot: &Table,
) -> Result<IcmpFlowType, CompilationError> {
    if !prot.contains_key("icmp_type") {
        return Err(err_config!("protocol {} missing icmp_type", prot_id));
    }
    if !prot.contains_key("icmp_codes") {
        return Err(err_config!("protocol {} missing icmp_codes", prot_id));
    }

    let codes = prot["icmp_codes"].as_array().ok_or(err_config!(
        "protocol {} icmp_codes is not an array",
        prot_id
    ))?;
    if codes.is_empty() {
        return Err(err_config!("protocol {} icmp_codes is empty", prot_id));
    }

    let ft = prot["icmp_type"]
        .as_str()
        .ok_or(err_config!("protocol {} icmp missing interaction", prot_id))?
        .to_string()
        .to_lowercase();

    let interaction: IcmpFlowType;

    if ft == zpl::ICMP_INTERACION_REQUEST_RESPONSE {
        if codes.len() != 2 {
            return Err(err_config!(
                "protocol {} icmp request-response requires exactly two type codes",
                prot_id
            ));
        }
        let code0 = toml_as_u8(&codes[0])
            .ok_or(err_config!("protocol {} icmp code[0] invalid", prot_id))?;
        let code1 = toml_as_u8(&codes[1])
            .ok_or(err_config!("protocol {} icmp code[1] invalid", prot_id))?;
        interaction = IcmpFlowType::RequestResponse(code0, code1);
    } else if ft == zpl::ICMP_INTERACTION_ONESHOT {
        let mut parsed_codes = Vec::new();
        for tcode in codes {
            let code = toml_as_u8(tcode).ok_or(err_config!(
                "protocol {} icmp code '{}' is invalid",
                prot_id,
                tcode
            ))?;
            parsed_codes.push(code);
        }
        interaction = IcmpFlowType::OneShot(parsed_codes);
    } else {
        return Err(err_config!(
            "protocol {} invalid icmp interaction type: {}",
            prot_id,
            ft
        ));
    }

    Ok(interaction)
}

/// Parse an individual protocol table.
/// Allow fields are:
/// - l4protocol (iana protocol name)
/// - 7lprotocol (app layer protocol name eg, HTTP or a ZPR protocol name)
/// - port (optional)
/// - icmp_type
/// - icmp_codes
pub(super) fn parse_protocol(
    prot_label: &str,
    prot: &Table,
    ctx: &CompilationCtx,
) -> Result<Protocol, CompilationError> {
    warn_unknown_prot_property(prot, ctx)?;
    if !prot.contains_key("l4protocol") {
        return Err(err_config!(
            "protocol {} missing key 'l4protocol'",
            prot_label
        ));
    }
    let protocol_name = prot["l4protocol"]
        .as_str()
        .ok_or(err_config!("protocol {} missing protocol", prot_label))?
        .to_string();
    let l7protocol = if prot.contains_key("l7protocol") {
        Some(
            prot["l7protocol"]
                .as_str()
                .ok_or(err_config!(
                    "protocol {} l7protocol is not a string",
                    prot_label
                ))?
                .to_string(),
        )
    } else {
        None
    };
    if let Some(l4) = IanaProtocol::parse(&protocol_name) {
        match l4 {
            IanaProtocol::TCP => {
                let mut bldr = Protocol::tcp(prot_label);
                let pspec = parse_tcp_udp_ports(prot_label, prot)?;
                bldr = bldr.add_ports(pspec);
                if let Some(l7) = l7protocol {
                    bldr = bldr.layer7(l7);
                }
                Ok(bldr.build()?)
            }
            IanaProtocol::UDP => {
                let mut bldr = Protocol::udp(prot_label);
                let pspec = parse_tcp_udp_ports(prot_label, prot)?;
                bldr = bldr.add_ports(pspec);
                if let Some(l7) = l7protocol {
                    bldr = bldr.layer7(l7);
                }
                Ok(bldr.build()?)
            }
            IanaProtocol::ICMP => {
                Ok(Protocol::icmp4(prot_label, parse_icmp_details(prot_label, prot)?).build()?)
            }
            IanaProtocol::ICMPv6 => {
                Ok(Protocol::icmp6(prot_label, parse_icmp_details(prot_label, prot)?).build()?)
            }
        }
    } else {
        Err(err_config!(
            "protocol {}: invalid l4 protocol name: {}",
            prot_label,
            protocol_name
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_tcp_udp_ports_single_port() {
        let mut table = Table::new();
        table.insert("port".to_string(), toml::Value::String("80".to_string()));

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], crate::protocols::PortSpec::Single(80));
    }

    #[test]
    fn test_parse_tcp_udp_ports_single_port_integer() {
        let mut table = Table::new();
        table.insert("port".to_string(), toml::Value::Integer(443));

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], crate::protocols::PortSpec::Single(443));
    }

    #[test]
    fn test_parse_tcp_udp_ports_multiple_ports() {
        let mut table = Table::new();
        table.insert(
            "port".to_string(),
            toml::Value::String("80,443,8080".to_string()),
        );

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0], crate::protocols::PortSpec::Single(80));
        assert_eq!(ports[1], crate::protocols::PortSpec::Single(443));
        assert_eq!(ports[2], crate::protocols::PortSpec::Single(8080));
    }

    #[test]
    fn test_parse_tcp_udp_ports_port_range() {
        let mut table = Table::new();
        table.insert(
            "port".to_string(),
            toml::Value::String("8000-9000".to_string()),
        );

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], crate::protocols::PortSpec::Range(8000, 9000));
    }

    #[test]
    fn test_parse_tcp_udp_ports_mixed_ports_and_ranges() {
        let mut table = Table::new();
        table.insert(
            "port".to_string(),
            toml::Value::String("22,80,8000-8999,443".to_string()),
        );

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 4);
        assert_eq!(ports[0], crate::protocols::PortSpec::Single(22));
        assert_eq!(ports[1], crate::protocols::PortSpec::Single(80));
        assert_eq!(ports[2], crate::protocols::PortSpec::Range(8000, 8999));
        assert_eq!(ports[3], crate::protocols::PortSpec::Single(443));
    }

    #[test]
    fn test_parse_tcp_udp_ports_with_spaces() {
        let mut table = Table::new();
        table.insert(
            "port".to_string(),
            toml::Value::String(" 80 , 443 , 8080 ".to_string()),
        );

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0], crate::protocols::PortSpec::Single(80));
        assert_eq!(ports[1], crate::protocols::PortSpec::Single(443));
        assert_eq!(ports[2], crate::protocols::PortSpec::Single(8080));
    }

    #[test]
    fn test_parse_tcp_udp_ports_missing_port() {
        let table = Table::new(); // Empty table, no port key

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_err());
        if let Err(CompilationError::ConfigError(msg)) = result {
            assert!(msg.contains("protocol test-protocol missing port"));
        } else {
            panic!("Expected ConfigError");
        }
    }

    #[test]
    fn test_parse_tcp_udp_ports_invalid_port_number() {
        let mut table = Table::new();
        table.insert(
            "port".to_string(),
            toml::Value::String("invalid".to_string()),
        );

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_err());
        if let Err(CompilationError::ConfigError(msg)) = result {
            assert!(msg.contains("protocol test-protocol invalid port specification"));
            assert!(msg.contains("invalid"));
        } else {
            panic!("Expected ConfigError");
        }
    }

    #[test]
    fn test_parse_tcp_udp_ports_invalid_port_range() {
        let mut table = Table::new();
        table.insert(
            "port".to_string(),
            toml::Value::String("8000-7000".to_string()),
        ); // Invalid range (start > end)

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_err());
        if let Err(CompilationError::ConfigError(msg)) = result {
            assert!(msg.contains("protocol test-protocol invalid port specification"));
        } else {
            panic!("Expected ConfigError");
        }
    }

    #[test]
    fn test_parse_tcp_udp_ports_zero_port() {
        let mut table = Table::new();
        table.insert("port".to_string(), toml::Value::String("0".to_string()));

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_err());
        if let Err(CompilationError::ConfigError(msg)) = result {
            assert!(msg.contains("protocol test-protocol invalid port specification"));
        } else {
            panic!("Expected ConfigError");
        }
    }

    #[test]
    fn test_parse_tcp_udp_ports_port_too_high() {
        let mut table = Table::new();
        table.insert("port".to_string(), toml::Value::String("65536".to_string())); // Port out of range

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_err());
        if let Err(CompilationError::ConfigError(msg)) = result {
            assert!(msg.contains("protocol test-protocol invalid port specification"));
        } else {
            panic!("Expected ConfigError");
        }
    }

    #[test]
    fn test_parse_tcp_udp_ports_malformed_range() {
        let mut table = Table::new();
        table.insert(
            "port".to_string(),
            toml::Value::String("8000-8500-9000".to_string()),
        ); // Too many dashes

        let result = parse_tcp_udp_ports("test-protocol", &table);
        assert!(result.is_err());
        if let Err(CompilationError::ConfigError(msg)) = result {
            assert!(msg.contains("protocol test-protocol invalid port specification"));
        } else {
            panic!("Expected ConfigError");
        }
    }
}
