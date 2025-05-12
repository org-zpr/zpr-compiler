pub const DEF_CLASS_SERVICE_NAME: &str = "service";
pub const DEF_CLASS_SERVICE_AKA: &str = "services";

pub const DEF_CLASS_USER_NAME: &str = "user";
pub const DEF_CLASS_USER_AKA: &str = "users";

pub const DEF_CLASS_DEVICE_NAME: &str = "device";
pub const DEF_CLASS_DEVICE_AKA: &str = "devices";

pub const DEFAULT_TRUSTED_SERVICE_ID: &str = "default";
pub const DEFAULT_TRUSTED_SERVICE_API: &str = TS_API_V1;

pub const TS_API_V1: &str = "validation/1";
pub const TS_API_V2: &str = "validation/2";

pub const ICMP_INTERACION_REQUEST_RESPONSE: &str = "request-response";
pub const ICMP_INTERACTION_ONESHOT: &str = "oneshot";

pub const VISA_SERVICE_CN: &str = "vs.zpr";
pub const ZPR_ADDR_ATTR: &str = "zpr.addr";

pub const DEFAULT_TS_PREFIX: &str = "device.zpr.adapter";
pub const DEFAULT_ATTR: &str = "cn";
pub const ADAPTER_CN_ATTR: &str = KATTR_CN;

// TODO: What is up with this odd name? Why not '/zpr/visaservice'?
pub const VS_SERVICE_NAME: &str = "/zpr/$$zpr/visaservice";

pub const KATTR_ROLE: &str = "zpr.role";
pub const KATTR_CN: &str = "device.zpr.adapter.cn";

pub const ATTR_DOMAIN_SERVICE: &str = "service";
pub const ATTR_DOMAIN_USER: &str = "user";
pub const ATTR_DOMAIN_DEVICE: &str = "device";
pub const ATTR_DOMAIN_ZPR_INTERNAL: &str = "zpr";

// For nodes to talk to VS
pub const VISA_SERVICE_PORT: u16 = 5002; // TCP

// For VS to talk to nodes
pub const VISA_SUPPORT_SEVICE_PORT: u16 = 8183; // TCP

// For admin to control the visa service (eg, install a policy)
#[allow(dead_code)]
pub const VISA_SERVICE_ADMIN_PORT: u16 = 8182; // TCP

// Only known config setting (see policy.proto)
pub const CONFIG_KEY_MAX_VISA_LIFETIME: u32 = 1; // value is time in seconds

// client (eg, adapter) facing
pub const ZPR_OAUTH_RSA_PORT_DEFAULT: u16 = 4000;

// visa service facing
pub const ZPR_VALIDATION2_PORT_DEFAULT: u16 = 3999;
