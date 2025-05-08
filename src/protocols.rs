use core::fmt;

use crate::zpl;

use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum ProtocolError {
    #[error("invalid protocol name: {0}")]
    InvalidProtocolName(String),

    #[error("invalid port for protocol: {0}")]
    InvalidPort(String),

    #[error("missing port for protocol: {0}")]
    MissingPort(String),

    #[error("missing ICMP flow type for protocol: {0}")]
    MissingIcmp(String),

    #[error("invalid ICMP flow type for protocol: {0}")]
    InvalidIcmp(String),
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum IanaProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMPv6 = 58,
}

/// These are built-in "layer7" protocols for ZPR. These are treated specially by
/// the compiler which knows how to create rules for them.  Users can use these
/// when configuring their authentication services.
pub const ZPR_OAUTH_RSA: &str = "zpr-oauthrsa";
pub const ZPR_VALIDATION_2: &str = "zpr-validation2";

pub const ZPR_L7_BUILTINS: [&str; 2] = [ZPR_OAUTH_RSA, ZPR_VALIDATION_2];

/// Protocol is an attempt to encompass the ZPL notion of a protocol.
/// It always must include a layer 3 protocol (eg TCP, UDP, ICMP).
/// It may also include a layer 7 protocol name.  Protocols from the
/// configuation always have a label (if we don't have an explicit
/// label the convention is to just use the layer7 name if we have it,
/// or the layer4 name if we don't).
#[derive(Debug, Clone)]
pub struct Protocol {
    label: String,
    layer7: Option<String>,
    layer4: IanaProtocol,
    port: Option<String>, // TODO: using string for now but needs to be a "port spec"
    icmp: Option<IcmpFlowType>,
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
        let s = s.trim_start_matches("iana.");
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

/// Part of a Protocol description.
#[derive(Debug, Clone, PartialEq)]
pub enum IcmpFlowType {
    RequestResponse(u8, u8),
    OneShot(Vec<u8>),
}

impl Protocol {
    /// Flexible constructor for a protocol.
    /// You can create partially valid protocols (eg, no port or icmp)
    pub fn new(
        label: &str,
        layer4: IanaProtocol,
        port: Option<String>,
        icmp: Option<IcmpFlowType>,
        layer7: Option<String>,
    ) -> Self {
        Protocol {
            label: label.to_string(),
            layer7,
            layer4,
            port,
            icmp,
        }
    }

    /// Create new for a ZPR namespace protocol.
    /// - `l7_protocol` is the layer 7 protocol name, eg "zpr-oauthrsa"
    pub fn new_zpr(
        label: &str,
        l7_protocol: &str,
        port: Option<String>,
    ) -> Result<Self, ProtocolError> {
        let (prot, port_adj) = match l7_protocol.to_lowercase().as_str() {
            ZPR_OAUTH_RSA => {
                let pp = if port.is_none() {
                    Some(zpl::ZPR_OAUTH_RSA_PORT_DEFAULT.to_string())
                } else {
                    port
                };
                (IanaProtocol::TCP, pp)
            }
            ZPR_VALIDATION_2 => {
                let pp = if port.is_none() {
                    Some(zpl::ZPR_VALIDATION2_PORT_DEFAULT.to_string())
                } else {
                    port
                };
                (IanaProtocol::TCP, pp)
            }
            _ => {
                return Err(ProtocolError::InvalidProtocolName(l7_protocol.to_string()));
            }
        };
        Ok(Protocol {
            label: label.to_string(),
            layer7: Some(l7_protocol.to_lowercase()),
            layer4: prot,
            port: port_adj,
            icmp: None,
        })
    }

    pub fn new_l7_with_port(
        label: &str,
        l7_protocol: &str,
        l4_protocol: IanaProtocol,
        port: Option<String>,
    ) -> Result<Self, ProtocolError> {
        if l7_protocol.starts_with("zpr.") {
            return Self::new_zpr(label, l7_protocol, port);
        }
        Ok(Protocol {
            label: label.to_string(),
            layer7: Some(l7_protocol.to_lowercase()),
            layer4: l4_protocol,
            port,
            icmp: None,
        })
    }

    pub fn new_l7_with_icmp(
        label: &str,
        l7_protocol: &str,
        l4_protocol: IanaProtocol,
        icmp: Option<IcmpFlowType>,
    ) -> Result<Self, ProtocolError> {
        if l7_protocol.starts_with("zpr.") {
            return Err(ProtocolError::InvalidIcmp(l7_protocol.to_string()));
        }
        Ok(Protocol {
            label: label.to_string(),
            layer7: Some(l7_protocol.to_lowercase()),
            layer4: l4_protocol,
            port: None,
            icmp,
        })
    }

    pub fn new_l4_with_port(label: &str, protocol: IanaProtocol, port: String) -> Self {
        Protocol {
            label: label.to_string(),
            layer7: None,
            layer4: protocol,
            port: Some(port),
            icmp: None,
        }
    }

    pub fn new_l4_with_icmp(label: &str, protocol: IanaProtocol, icmp: IcmpFlowType) -> Self {
        Protocol {
            label: label.to_string(),
            layer7: None,
            layer4: protocol,
            port: None,
            icmp: Some(icmp),
        }
    }

    pub fn set_port(&mut self, port: &str) {
        if !self.layer4.takes_port_arg() {
            panic!("Protocol::set_port called on non-port protocol");
        }
        self.port = Some(port.to_string());
    }

    pub fn set_icmp(&mut self, icmp: &IcmpFlowType) {
        if !self.layer4.is_icmp() {
            panic!("Protocol::set_icmp called on non-icmp protocol");
        }
        self.icmp = Some(icmp.clone());
    }

    pub fn get_label(&self) -> &String {
        &self.label
    }

    pub fn get_layer7(&self) -> Option<&String> {
        self.layer7.as_ref()
    }

    pub fn set_layer7(&mut self, layer7: &str) {
        self.layer7 = Some(layer7.to_string());
    }

    pub fn get_layer4(&self) -> IanaProtocol {
        self.layer4
    }

    pub fn get_port(&self) -> Option<&String> {
        self.port.as_ref()
    }

    pub fn get_icmp(&self) -> Option<&IcmpFlowType> {
        self.icmp.as_ref()
    }

    pub fn is_icmp(&self) -> bool {
        self.layer4.is_icmp()
    }

    pub fn has_port(&self) -> bool {
        self.port.is_some()
    }

    pub fn to_endpoint_str(&self) -> String {
        let mut s = String::new();
        let protname = self.layer4.to_string().to_uppercase();
        if self.layer4.is_icmp() {
            if let Some(ref icmp) = self.icmp {
                match icmp {
                    IcmpFlowType::RequestResponse(req, resp) => {
                        s.push_str(&format!("{}/{}", protname, req));
                        s.push_str(&format!(",{}/{}", protname, resp));
                    }
                    IcmpFlowType::OneShot(ref codes) => {
                        for c in codes {
                            s.push_str(&format!("{}/{}", protname, c));
                        }
                    }
                }
            } else {
                s.push_str(&format!("{}/0", protname));
            }
        } else {
            s.push_str(&format!("{}/", protname));
            if let Some(ref port) = self.port {
                s.push_str(port);
            } else {
                s.push('0');
            }
        }
        s
    }
}
