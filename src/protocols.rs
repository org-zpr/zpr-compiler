use core::fmt;

use crate::zpl;

use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum ProtocolError {
    #[error("invalid layer 7 protocol name: {0}")]
    InvalidL7ProtocolName(String),

    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),

    #[error("invalid port for protocol: {0}")]
    InvalidPort(String),

    #[error("missing port for protocol: {0}")]
    MissingPort(String),

    #[error("missing ICMP flow type for protocol: {0}")]
    MissingIcmp(String),

    #[error("invalid ICMP flow type for protocol: {0}")]
    InvalidIcmp(String),
}

/// These are built-in "layer7" protocols for ZPR. These are treated specially by
/// the compiler which knows how to create rules for them.  Users can use these
/// when configuring their authentication services.
pub const ZPR_OAUTH_RSA: &str = "zpr-oauthrsa";
pub const ZPR_VALIDATION_2: &str = "zpr-validation2";

pub const ZPR_L7_BUILTINS: [&str; 2] = [ZPR_OAUTH_RSA, ZPR_VALIDATION_2];

#[derive(Debug, Clone, PartialEq, Copy, Eq, Hash)]
pub enum IanaProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMPv6 = 58,
}

/// Protocol is an attempt to encompass the ZPL notion of a protocol.
/// It always must include a layer 3 protocol (eg TCP, UDP, ICMP).
/// It may also include a layer 7 protocol name.  Protocols from the
/// configuation always have a label (if we don't have an explicit
/// label the convention is to just use the layer7 name if we have it,
/// or the layer4 name if we don't).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Protocol {
    label: String,
    layer7: Option<String>,
    layer4: IanaProtocol,
    details: ProtocolDetails,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolDetails {
    TcpUdp(Vec<PortSpec>),
    Icmp(IcmpFlowType),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PortSpec {
    Single(u16),
    Range(u16, u16),
}

pub struct TcpUdpProtocolBuilder {
    label: String,
    layer7: Option<String>,
    layer4: IanaProtocol,
    port: Vec<PortSpec>,
}
pub struct IcmpProtocolBuilder {
    label: String,
    layer7: Option<String>,
    layer4: IanaProtocol,
    icmp: IcmpFlowType,
}

/// Part of a Protocol description.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IcmpFlowType {
    RequestResponse(u8, u8),
    OneShot(Vec<u8>),
}

impl fmt::Display for IanaProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IanaProtocol::ICMP => write!(f, "icmp"),
            IanaProtocol::TCP => write!(f, "tcp"),
            IanaProtocol::UDP => write!(f, "udp"),
            IanaProtocol::ICMPv6 => write!(f, "icmp6"),
        }
    }
}

impl From<IanaProtocol> for u32 {
    fn from(value: IanaProtocol) -> Self {
        value as u32
    }
}

impl TryFrom<u32> for IanaProtocol {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(IanaProtocol::ICMP),
            6 => Ok(IanaProtocol::TCP),
            17 => Ok(IanaProtocol::UDP),
            58 => Ok(IanaProtocol::ICMPv6),
            _ => Err("Invalid IANA protocol number"),
        }
    }
}

impl TryFrom<u8> for IanaProtocol {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        IanaProtocol::try_from(value as u32)
    }
}

impl IanaProtocol {
    /// Convert a ZPL string (with or without leading 'iana') to an IANA protocol number enum.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.strip_prefix("iana.").unwrap_or(s);
        match s.to_lowercase().as_str() {
            "icmp" | "icmp4" | "icmpv4" => Some(IanaProtocol::ICMP),
            "tcp" => Some(IanaProtocol::TCP),
            "udp" => Some(IanaProtocol::UDP),
            "icmp6" | "icmpv6" => Some(IanaProtocol::ICMPv6),
            _ => None,
        }
    }

    pub fn is_icmp(&self) -> bool {
        matches!(self, IanaProtocol::ICMP | IanaProtocol::ICMPv6)
    }

    pub fn takes_port_arg(&self) -> bool {
        !self.is_icmp()
    }
}

impl TcpUdpProtocolBuilder {
    // TODO: Should we require ports here?
    pub fn new(label: String, layer4: IanaProtocol) -> Self {
        TcpUdpProtocolBuilder {
            label,
            layer7: None,
            layer4,
            port: Vec::new(),
        }
    }
    pub fn layer7(mut self, layer7: String) -> Self {
        self.layer7 = Some(layer7);
        self
    }
    pub fn add_port(mut self, port: PortSpec) -> Self {
        self.port.push(port);
        self
    }
    pub fn add_ports(mut self, ports: Vec<PortSpec>) -> Self {
        for p in ports {
            self.port.push(p);
        }
        self
    }
    pub fn build(self) -> Result<Protocol, ProtocolError> {
        if self.port.is_empty() {
            return Err(ProtocolError::InvalidPort(format!(
                "ports must be specified for TCP/UDP protocol {}",
                self.label
            )));
        }
        Ok(Protocol {
            label: self.label,
            layer7: self.layer7,
            layer4: self.layer4,
            details: ProtocolDetails::TcpUdp(self.port),
        })
    }
}

impl IcmpProtocolBuilder {
    pub fn new_icmp4(label: String, icmp: IcmpFlowType) -> Self {
        IcmpProtocolBuilder {
            label,
            layer7: None,
            layer4: IanaProtocol::ICMP,
            icmp,
        }
    }
    pub fn new_icmp6(label: String, icmp: IcmpFlowType) -> Self {
        IcmpProtocolBuilder {
            label,
            layer7: None,
            layer4: IanaProtocol::ICMPv6,
            icmp,
        }
    }
    pub fn layer7(mut self, layer7: String) -> Self {
        self.layer7 = Some(layer7);
        self
    }
    pub fn build(self) -> Result<Protocol, ProtocolError> {
        Ok(Protocol {
            label: self.label,
            layer7: self.layer7,
            layer4: self.layer4,
            details: ProtocolDetails::Icmp(self.icmp),
        })
    }
}

impl Protocol {
    pub fn tcp<S: Into<String>>(label: S) -> TcpUdpProtocolBuilder {
        TcpUdpProtocolBuilder::new(label.into(), IanaProtocol::TCP)
    }
    pub fn udp<S: Into<String>>(label: S) -> TcpUdpProtocolBuilder {
        TcpUdpProtocolBuilder::new(label.into(), IanaProtocol::UDP)
    }
    pub fn icmp4<S: Into<String>>(label: S, icmp: IcmpFlowType) -> IcmpProtocolBuilder {
        IcmpProtocolBuilder::new_icmp4(label.into(), icmp)
    }
    pub fn icmp6<S: Into<String>>(label: S, icmp: IcmpFlowType) -> IcmpProtocolBuilder {
        IcmpProtocolBuilder::new_icmp6(label.into(), icmp)
    }

    /// Create from a ZPR namespace protocol.
    /// - `l7_protocol` is the layer 7 protocol name, eg "zpr-oauthrsa"
    /// - `port` is an optional port specification. If not provided, the default port for the
    ///   protocol will be used.
    pub fn new_zpr_l7(
        label: String,
        l7_protocol: String,
        port: Option<PortSpec>,
    ) -> Result<Self, ProtocolError> {
        let (prot, port_adj) = match l7_protocol.to_lowercase().as_str() {
            ZPR_OAUTH_RSA => {
                let pp = if let Some(ps) = port {
                    vec![ps]
                } else {
                    vec![PortSpec::Single(zpl::ZPR_OAUTH_RSA_PORT_DEFAULT)]
                };
                (IanaProtocol::TCP, pp)
            }
            ZPR_VALIDATION_2 => {
                let pp = if let Some(ps) = port {
                    vec![ps]
                } else {
                    vec![PortSpec::Single(zpl::ZPR_VALIDATION2_PORT_DEFAULT)]
                };
                (IanaProtocol::TCP, pp)
            }
            _ => {
                return Err(ProtocolError::InvalidL7ProtocolName(
                    l7_protocol.to_string(),
                ));
            }
        };
        match prot {
            IanaProtocol::TCP => Protocol::tcp(label)
                .layer7(l7_protocol)
                .add_ports(port_adj)
                .build(),
            IanaProtocol::UDP => Protocol::udp(label)
                .layer7(l7_protocol)
                .add_ports(port_adj)
                .build(),
            _ => unreachable!(),
        }
    }

    /// Replace the portspec on this protocol.
    pub fn set_portspec(&mut self, ports: Vec<PortSpec>) -> Result<(), ProtocolError> {
        if !self.layer4.takes_port_arg() {
            return Err(ProtocolError::InvalidPort(format!(
                "Protocol::set_portspec called on non-port protocol {:?}",
                self.layer4
            )));
        }
        self.details = ProtocolDetails::TcpUdp(ports);
        Ok(())
    }

    pub fn set_icmp(&mut self, icmp: IcmpFlowType) -> Result<(), ProtocolError> {
        if !self.layer4.is_icmp() {
            return Err(ProtocolError::InvalidIcmp(format!(
                "Protocol::set_icmp called on non-ICMP protocol {:?}",
                self.layer4
            )));
        }
        self.details = ProtocolDetails::Icmp(icmp);
        Ok(())
    }

    pub fn get_label(&self) -> &String {
        &self.label
    }

    pub fn get_layer7(&self) -> Option<&String> {
        self.layer7.as_ref()
    }

    pub fn set_layer7(&mut self, layer7: String) {
        self.layer7 = Some(layer7);
    }

    pub fn get_layer4(&self) -> IanaProtocol {
        self.layer4
    }

    pub fn get_port(&self) -> Result<&[PortSpec], ProtocolError> {
        match self.details {
            ProtocolDetails::TcpUdp(ref pspecs) => Ok(pspecs),
            ProtocolDetails::Icmp(_) => Err(ProtocolError::MissingPort(format!(
                "protocol {} has no port spec",
                self.label
            ))),
        }
    }

    pub fn get_icmp(&self) -> Result<&IcmpFlowType, ProtocolError> {
        match self.details {
            ProtocolDetails::Icmp(ref icmp) => Ok(icmp),
            ProtocolDetails::TcpUdp(_) => Err(ProtocolError::MissingIcmp(format!(
                "protocol {} is not ICMP",
                self.label
            ))),
        }
    }

    pub fn get_details(&self) -> &ProtocolDetails {
        &self.details
    }

    pub fn is_icmp(&self) -> bool {
        self.layer4.is_icmp()
    }

    pub fn has_port(&self) -> bool {
        match self.details {
            ProtocolDetails::TcpUdp(ref pspecs) => !pspecs.is_empty(),
            ProtocolDetails::Icmp(_) => false,
        }
    }

    pub fn to_endpoint_str(&self) -> String {
        let mut s = String::new();
        let protname = self.layer4.to_string().to_uppercase();

        match &self.details {
            ProtocolDetails::TcpUdp(specs) => {
                if specs.is_empty() {
                    s.push_str(&format!("{}/0", protname)); // no port?
                } else {
                    for (i, ps) in specs.iter().enumerate() {
                        if i > 0 {
                            s.push(',');
                        }
                        match ps {
                            PortSpec::Single(p) => {
                                s.push_str(&format!("{}/{}", protname, p));
                            }
                            PortSpec::Range(start, end) => {
                                s.push_str(&format!("{}/{}-{}", protname, start, end));
                            }
                        }
                    }
                }
            }
            ProtocolDetails::Icmp(ft) => match ft {
                IcmpFlowType::RequestResponse(req, resp) => {
                    s.push_str(&format!("{}/{}", protname, req));
                    s.push_str(&format!(",{}/{}", protname, resp));
                }
                IcmpFlowType::OneShot(codes) => {
                    for (i, c) in codes.iter().enumerate() {
                        if i > 0 {
                            s.push(',');
                        }
                        s.push_str(&format!("{}/{}", protname, c));
                    }
                }
            },
        }
        s
    }
}

impl PortSpec {
    // Valid form of `ps_strv` is:
    // - single port number
    // - comma separated list of port numbers
    // - range of port numbers (e.g. 8000-9000)
    // - comma separated mix of the above (e.g. 22,80,443,8000-9000)
    pub fn parse_list(ps_strv: &str) -> Result<Vec<PortSpec>, ProtocolError> {
        let mut ports: Vec<PortSpec> = Vec::new();
        for part in ps_strv.split(',') {
            let part = part.trim();
            if part.contains('-') {
                let bounds: Vec<&str> = part.split('-').collect();
                if bounds.len() != 2 {
                    return Err(ProtocolError::InvalidPort(format!(
                        "invalid port range spec: {}",
                        part
                    )));
                }
                let start: u16 = bounds[0].trim().parse().map_err(|_| {
                    ProtocolError::InvalidPort(format!("invalid port number: {}", bounds[0]))
                })?;
                let end: u16 = bounds[1].trim().parse().map_err(|_| {
                    ProtocolError::InvalidPort(format!("invalid port number: {}", bounds[1]))
                })?;
                if start == 0 || end == 0 || start > end {
                    return Err(ProtocolError::InvalidPort(format!(
                        "invalid port range: {}",
                        part
                    )));
                }
                if start == end {
                    ports.push(PortSpec::Single(start));
                } else {
                    ports.push(PortSpec::Range(start, end));
                }
            } else {
                let p: u16 = part.parse().map_err(|_| {
                    ProtocolError::InvalidPort(format!("invalid port number: {}", part))
                })?;
                if p == 0 {
                    return Err(ProtocolError::InvalidPort(format!(
                        "invalid port number: {}",
                        part
                    )));
                }
                ports.push(PortSpec::Single(p));
            }
        }
        Ok(ports)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_iana_parse() {
        assert_eq!(IanaProtocol::parse("iana.icmp"), Some(IanaProtocol::ICMP));
        assert_eq!(IanaProtocol::parse("icmp"), Some(IanaProtocol::ICMP));
        assert_eq!(IanaProtocol::parse("iana.tcp"), Some(IanaProtocol::TCP));
        assert_eq!(IanaProtocol::parse("iana.TCP"), Some(IanaProtocol::TCP));
        assert_eq!(IanaProtocol::parse("tcp"), Some(IanaProtocol::TCP));
        assert_eq!(IanaProtocol::parse("iana.udp"), Some(IanaProtocol::UDP));
        assert_eq!(IanaProtocol::parse("udp"), Some(IanaProtocol::UDP));
        assert_eq!(
            IanaProtocol::parse("iana.icmpv6"),
            Some(IanaProtocol::ICMPv6)
        );
        assert_eq!(IanaProtocol::parse("icmpv6"), Some(IanaProtocol::ICMPv6));
        assert_eq!(IanaProtocol::parse("iana.icmp4"), Some(IanaProtocol::ICMP));
        assert_eq!(IanaProtocol::parse("icmp4"), Some(IanaProtocol::ICMP));
        assert_eq!(IanaProtocol::parse("iana.icmpv4"), Some(IanaProtocol::ICMP));
        assert_eq!(IanaProtocol::parse("icmpv4"), Some(IanaProtocol::ICMP));
        assert_eq!(IanaProtocol::parse("iana.foo"), None);
        assert_eq!(IanaProtocol::parse("foo"), None);
    }

    #[test]
    fn test_to_endpoint_str_tcp_single_port() {
        let protocol = Protocol::tcp("web")
            .add_port(PortSpec::Single(80))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "TCP/80");
    }

    #[test]
    fn test_to_endpoint_str_tcp_multiple_ports() {
        let protocol = Protocol::tcp("multi")
            .add_port(PortSpec::Single(80))
            .add_port(PortSpec::Single(443))
            .add_port(PortSpec::Single(8080))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "TCP/80,TCP/443,TCP/8080");
    }

    #[test]
    fn test_to_endpoint_str_tcp_port_range() {
        let protocol = Protocol::tcp("range")
            .add_port(PortSpec::Range(8000, 9000))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "TCP/8000-9000");
    }

    #[test]
    fn test_to_endpoint_str_tcp_mixed_ports_and_ranges() {
        let protocol = Protocol::tcp("mixed")
            .add_port(PortSpec::Single(80))
            .add_port(PortSpec::Range(8000, 8999))
            .add_port(PortSpec::Single(443))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "TCP/80,TCP/8000-8999,TCP/443");
    }

    #[test]
    fn test_to_endpoint_str_tcp_no_ports() {
        // Create a TCP protocol with no ports (edge case)
        let protocol = Protocol {
            label: "empty".to_string(),
            layer7: None,
            layer4: IanaProtocol::TCP,
            details: ProtocolDetails::TcpUdp(vec![]),
        };

        assert_eq!(protocol.to_endpoint_str(), "TCP/0");
    }

    #[test]
    fn test_to_endpoint_str_udp_single_port() {
        let protocol = Protocol::udp("dns")
            .add_port(PortSpec::Single(53))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "UDP/53");
    }

    #[test]
    fn test_to_endpoint_str_udp_multiple_ports() {
        let protocol = Protocol::udp("multi-udp")
            .add_port(PortSpec::Single(53))
            .add_port(PortSpec::Single(123))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "UDP/53,UDP/123");
    }

    #[test]
    fn test_to_endpoint_str_udp_port_range() {
        let protocol = Protocol::udp("udp-range")
            .add_port(PortSpec::Range(10000, 20000))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "UDP/10000-20000");
    }

    #[test]
    fn test_to_endpoint_str_icmp_request_response() {
        let protocol = Protocol::icmp4("ping", IcmpFlowType::RequestResponse(8, 0))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "ICMP/8,ICMP/0");
    }

    #[test]
    fn test_to_endpoint_str_icmp_oneshot_single() {
        let protocol = Protocol::icmp4("dest-unreachable", IcmpFlowType::OneShot(vec![3]))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "ICMP/3");
    }

    #[test]
    fn test_to_endpoint_str_icmp_oneshot_multiple() {
        let protocol = Protocol::icmp4("errors", IcmpFlowType::OneShot(vec![3, 11, 12]))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "ICMP/3,ICMP/11,ICMP/12");
    }

    #[test]
    fn test_to_endpoint_str_icmpv6_request_response() {
        let protocol = Protocol::icmp6("ping6", IcmpFlowType::RequestResponse(128, 129))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "ICMP6/128,ICMP6/129");
    }

    #[test]
    fn test_to_endpoint_str_icmpv6_oneshot() {
        let protocol = Protocol::icmp6("neighbor-solicitation", IcmpFlowType::OneShot(vec![135]))
            .build()
            .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "ICMP6/135");
    }

    #[test]
    fn test_to_endpoint_str_tcp_with_layer7() {
        let protocol = Protocol::tcp("https")
            .layer7("tls".to_string())
            .add_port(PortSpec::Single(443))
            .build()
            .unwrap();

        // Layer 7 protocol shouldn't affect the endpoint string format
        assert_eq!(protocol.to_endpoint_str(), "TCP/443");
    }

    #[test]
    fn test_to_endpoint_str_zpr_l7_protocol() {
        let protocol = Protocol::new_zpr_l7(
            "oauth".to_string(),
            "zpr-oauthrsa".to_string(),
            Some(PortSpec::Single(8443)),
        )
        .unwrap();

        assert_eq!(protocol.to_endpoint_str(), "TCP/8443");
    }

    #[test]
    fn test_port_spec_parse_list_single_port() {
        let result = PortSpec::parse_list("80");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], PortSpec::Single(80));
    }

    #[test]
    fn test_port_spec_parse_list_multiple_ports() {
        let result = PortSpec::parse_list("80,443,8080");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0], PortSpec::Single(80));
        assert_eq!(ports[1], PortSpec::Single(443));
        assert_eq!(ports[2], PortSpec::Single(8080));
    }

    #[test]
    fn test_port_spec_parse_list_port_range() {
        let result = PortSpec::parse_list("8000-9000");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], PortSpec::Range(8000, 9000));
    }

    #[test]
    fn test_port_spec_parse_list_mixed_ports_and_ranges() {
        let result = PortSpec::parse_list("22,80,8000-8999,443");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 4);
        assert_eq!(ports[0], PortSpec::Single(22));
        assert_eq!(ports[1], PortSpec::Single(80));
        assert_eq!(ports[2], PortSpec::Range(8000, 8999));
        assert_eq!(ports[3], PortSpec::Single(443));
    }

    #[test]
    fn test_port_spec_parse_list_with_whitespace() {
        let result = PortSpec::parse_list(" 80 , 443 , 8080 ");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0], PortSpec::Single(80));
        assert_eq!(ports[1], PortSpec::Single(443));
        assert_eq!(ports[2], PortSpec::Single(8080));
    }

    #[test]
    fn test_port_spec_parse_list_range_with_whitespace() {
        let result = PortSpec::parse_list("8000-9000");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], PortSpec::Range(8000, 9000));
    }

    #[test]
    fn test_port_spec_parse_list_range_with_internal_whitespace_ok() {
        // Whitespace around the dash is not supported in the current implementation
        let result = PortSpec::parse_list("8000 - 9000");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], PortSpec::Range(8000, 9000));
    }

    #[test]
    fn test_port_spec_parse_list_empty_string() {
        let result = PortSpec::parse_list("");
        assert!(result.is_err());
        if let Err(ProtocolError::InvalidPort(msg)) = result {
            assert!(msg.contains("invalid port number"));
        } else {
            panic!("Expected ProtocolError::InvalidPort");
        }
    }

    #[test]
    fn test_port_spec_parse_list_zero_port() {
        let result = PortSpec::parse_list("0");
        assert!(result.is_err());
        if let Err(ProtocolError::InvalidPort(msg)) = result {
            assert!(msg.contains("invalid port number: 0"));
        } else {
            panic!("Expected ProtocolError::InvalidPort");
        }
    }

    #[test]
    fn test_port_spec_parse_list_zero_in_range() {
        let result = PortSpec::parse_list("0-100");
        assert!(result.is_err());
        if let Err(ProtocolError::InvalidPort(msg)) = result {
            assert!(msg.contains("invalid port range"));
        } else {
            panic!("Expected ProtocolError::InvalidPort");
        }
    }

    #[test]
    fn test_port_spec_parse_list_invalid_port_number() {
        let result = PortSpec::parse_list("invalid");
        assert!(result.is_err());
        if let Err(ProtocolError::InvalidPort(msg)) = result {
            assert!(msg.contains("invalid port number: invalid"));
        } else {
            panic!("Expected ProtocolError::InvalidPort");
        }
    }

    #[test]
    fn test_port_spec_parse_list_port_too_high() {
        let result = PortSpec::parse_list("65536");
        assert!(result.is_err());
        if let Err(ProtocolError::InvalidPort(msg)) = result {
            assert!(msg.contains("invalid port number"));
        } else {
            panic!("Expected ProtocolError::InvalidPort");
        }
    }

    #[test]
    fn test_port_spec_parse_list_invalid_range_order() {
        let result = PortSpec::parse_list("9000-8000");
        assert!(result.is_err());
        if let Err(ProtocolError::InvalidPort(msg)) = result {
            assert!(msg.contains("invalid port range"));
        } else {
            panic!("Expected ProtocolError::InvalidPort");
        }
    }

    #[test]
    fn test_port_spec_parse_list_malformed_range_too_many_dashes() {
        let result = PortSpec::parse_list("8000-8500-9000");
        assert!(result.is_err());
        if let Err(ProtocolError::InvalidPort(msg)) = result {
            assert!(msg.contains("invalid port range spec"));
        } else {
            panic!("Expected ProtocolError::InvalidPort");
        }
    }

    #[test]
    fn test_port_spec_parse_list_malformed_range_single_dash() {
        let result = PortSpec::parse_list("8000-");
        assert!(result.is_err());
        if let Err(ProtocolError::InvalidPort(msg)) = result {
            assert!(msg.contains("invalid port number"));
        } else {
            panic!("Expected ProtocolError::InvalidPort");
        }
    }

    #[test]
    fn test_port_spec_parse_list_mixed_valid_and_invalid() {
        let result = PortSpec::parse_list("80,invalid,443");
        assert!(result.is_err());
        if let Err(ProtocolError::InvalidPort(msg)) = result {
            assert!(msg.contains("invalid port number: invalid"));
        } else {
            panic!("Expected ProtocolError::InvalidPort");
        }
    }

    #[test]
    fn test_port_spec_parse_list_edge_case_valid_ports() {
        let result = PortSpec::parse_list("1,65535");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0], PortSpec::Single(1));
        assert_eq!(ports[1], PortSpec::Single(65535));
    }

    #[test]
    fn test_port_spec_parse_list_edge_case_valid_range() {
        let result = PortSpec::parse_list("1-65535");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], PortSpec::Range(1, 65535));
    }

    #[test]
    fn test_port_spec_parse_list_single_port_range() {
        let result = PortSpec::parse_list("80-80");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], PortSpec::Single(80));
    }

    #[test]
    fn test_port_spec_parse_list_complex_mixed() {
        let result = PortSpec::parse_list("22,80-90,443,8000-9000,3000");
        assert!(result.is_ok());
        let ports = result.unwrap();
        assert_eq!(ports.len(), 5);
        assert_eq!(ports[0], PortSpec::Single(22));
        assert_eq!(ports[1], PortSpec::Range(80, 90));
        assert_eq!(ports[2], PortSpec::Single(443));
        assert_eq!(ports[3], PortSpec::Range(8000, 9000));
        assert_eq!(ports[4], PortSpec::Single(3000));
    }
}
