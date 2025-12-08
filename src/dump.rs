use colored::Colorize;
#[cfg(feature = "v1")]
use polio::polio;
#[cfg(feature = "v1")]
use std::convert::TryInto;
use std::net::IpAddr;

#[cfg(feature = "v1")]
use crate::protocols::IanaProtocol;
use crate::zpl;

pub fn print_section_hdr(title: &str) {
    println!();
    println!(
        "{}{}{} {}",
        String::from("═").red(),
        String::from("═").white(),
        String::from("═").blue(),
        title.green().bold()
    );
}

pub fn config_setting_key_to_string(key: u32) -> String {
    match key {
        zpl::CONFIG_KEY_MAX_VISA_LIFETIME => String::from("max_visa_lifetime"),
        _ => format!("key #{}", key),
    }
}

#[cfg(feature = "v1")]
pub fn config_val_to_string(optval: &Option<polio::config_setting::Val>) -> String {
    match optval {
        Some(polio::config_setting::Val::Sv(s)) => s.clone(),
        Some(polio::config_setting::Val::U32v(n)) => format!("{}", n),
        Some(polio::config_setting::Val::U64v(n)) => format!("{}", n),
        Some(polio::config_setting::Val::Bv(b)) => format!("{}", b),
        None => String::from("null"),
    }
}

pub fn parse_addr_to_string(addr_bytes: &[u8]) -> String {
    match parse_addr(addr_bytes) {
        Ok(addr) => addr.to_string(),
        Err(_) => String::from("!INVALID_ADDR!"),
    }
}

/// Parse IpAddr out of byte array.
fn parse_addr(addr_bytes: &[u8]) -> Result<IpAddr, String> {
    if addr_bytes.len() == 4 {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(addr_bytes);
        Ok(IpAddr::from(addr))
    } else if addr_bytes.len() == 16 {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(addr_bytes);
        Ok(IpAddr::from(addr))
    } else {
        Err(format!("Invalid address length: {}", addr_bytes.len()))
    }
}

#[cfg(feature = "v1")]
pub fn instrs_to_strings(instrs: &[polio::Instruction]) -> Vec<String> {
    instrs.iter().map(instr_to_string).collect::<Vec<String>>()
}

#[cfg(feature = "v1")]
fn instr_to_string(instr: &polio::Instruction) -> String {
    let mut sb = String::new();
    sb.push_str(&format!("{} ", opcode_to_string(instr.opcode)));
    for arg_opt in &instr.args {
        if let Some(arg) = &arg_opt.arg {
            match arg {
                polio::argument::Arg::Ival(n) => sb.push_str(&format!("{}", n)),
                polio::argument::Arg::Uival(n) => sb.push_str(&format!("{}", n)),
                polio::argument::Arg::Strval(s) => sb.push_str(&format!("'{}'", s)),
                polio::argument::Arg::Bval(b) => sb.push_str(&format!("{}", b)),
                polio::argument::Arg::Flagval(f) => sb.push_str(&flagt_to_string(*f)),
                polio::argument::Arg::Svcval(s) => sb.push_str(&svct_to_string(*s)),
                polio::argument::Arg::Spval(tuple) => {
                    sb.push_str(&format!("({}, {})", tuple.a, tuple.b))
                }
                polio::argument::Arg::Insval(i) => sb.push_str(&instr_to_string(i)), // recurse!
            }
            sb.push_str("  ");
        }
    }
    sb
}

#[cfg(feature = "v1")]
fn opcode_to_string(opcode: i32) -> String {
    String::from(match polio::OpCodeT::try_from(opcode) {
        Ok(t) => t.as_str_name(),
        Err(_) => "!ERR!",
    })
}

#[cfg(feature = "v1")]
fn flagt_to_string(flag: i32) -> String {
    String::from(match polio::FlagT::try_from(flag) {
        Ok(f) => f.as_str_name(),
        Err(_) => "!ERR!",
    })
}

#[cfg(feature = "v1")]
pub fn svct_to_string(svct: i32) -> String {
    String::from(match polio::SvcT::try_from(svct) {
        Ok(st) => st.as_str_name(),
        Err(_) => "!ERR!",
    })
}

#[cfg(feature = "v1")]
pub fn scopes_to_string(scopes: &[polio::Scope]) -> String {
    scopes
        .iter()
        .map(scope_to_string)
        .collect::<Vec<String>>()
        .join(", ")
}

#[cfg(feature = "v1")]
fn scope_to_string(scope: &polio::Scope) -> String {
    let proto: IanaProtocol = match scope.protocol.try_into() {
        Ok(p) => p,
        Err(_) => {
            return String::from("!INVALID_PROTOCOL!");
        }
    };
    let mut s = String::new();
    s.push_str(&proto.to_string());
    if let Some(pa) = &scope.protarg {
        match pa {
            polio::scope::Protarg::Pspec(pslist) => {
                for ps in &pslist.spec {
                    if let Some(psp) = &ps.parg {
                        match psp {
                            polio::port_spec::Parg::Port(pnum) => {
                                s.push_str(&format!(" {pnum}"));
                            }
                            polio::port_spec::Parg::Pr(prange) => {
                                s.push_str(&format!(" {}-{}", prange.low, prange.high));
                            }
                        }
                    }
                }
            }
            polio::scope::Protarg::Icmp(icmp) => {
                match polio::Icmpt::try_from(icmp.r#type) {
                    Ok(t) => s.push_str(&format!(" {} ", t.as_str_name())),
                    Err(_) => s.push_str(" !ERR! "),
                }
                s.push_str(&format!(" codes:{:?}", icmp.codes));
            }
        }
    }
    s
}

#[cfg(feature = "v1")]
pub fn attr_exp_to_string(exp: &polio::AttrExpr, keys: &[String], values: &[String]) -> String {
    let mut s = String::new();
    s.push_str(&keys[exp.key as usize]);
    s.push_str(&format!(" {} ", attr_opt_t_to_string(exp.op)));
    s.push_str(&values[exp.val as usize]);
    s
}

#[cfg(feature = "v1")]
fn attr_opt_t_to_string(opval: i32) -> String {
    String::from(match polio::AttrOpT::try_from(opval) {
        Ok(o) => o.as_str_name(),
        Err(_) => "!ERR!",
    })
}

pub fn array_to_string(arr: &[String]) -> String {
    if arr.is_empty() {
        return String::from("[]");
    }
    let mut s = String::new();
    s.push('[');
    s.push_str(&arr.join(", "));
    s.push(']');
    s
}
