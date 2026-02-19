use crate::zpl;
use colored::Colorize;
use std::net::IpAddr;

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
