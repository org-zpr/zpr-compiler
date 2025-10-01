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
                    for c in codes {
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
                let start: u16 = bounds[0].parse().map_err(|_| {
                    ProtocolError::InvalidPort(format!("invalid port number: {}", bounds[0]))
                })?;
                let end: u16 = bounds[1].parse().map_err(|_| {
                    ProtocolError::InvalidPort(format!("invalid port number: {}", bounds[1]))
                })?;
                if start == 0 || end == 0 || start > end {
                    return Err(ProtocolError::InvalidPort(format!(
                        "invalid port range: {}",
                        part
                    )));
                }
                ports.push(PortSpec::Range(start, end));
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
}
