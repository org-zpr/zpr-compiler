use ::polio::policy_capnp;
use clap::Parser;
use colored::Colorize;
use polio::polio;
use std::convert::TryInto;
use std::net::IpAddr;
use std::path::PathBuf;

use base64::prelude::*;
use bytes::Bytes;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use prost::Message;

use zplc::compiler::get_compiler_version;
use zplc::policybinaryv1::NO_PROC;
use zplc::protocols::IanaProtocol;
use zplc::zpl;

/// ZPL Policy Dumper
///
/// Prints contents of a binary policy file to stdout.
#[derive(Debug, Parser)]
#[command(name = "zpdump")]
#[command(version, verbatim_doc_comment)]
struct Cli {
    /// Path to the ZPL file.
    #[arg(value_name = "ZPL_FILE")]
    zpl: PathBuf,
}

fn main() {
    let exit_code = 0;
    let cli = Cli::parse();

    let fname = cli.zpl.display().to_string();
    let encoded = std::fs::read(cli.zpl).expect("failed to read binary policy file");
    let encoded_buf = Bytes::from(encoded);
    if fname.ends_with(".bin2") {
        dump_v2(&fname, encoded_buf);
    } else {
        dump_v1(&fname, encoded_buf);
    }
    std::process::exit(exit_code);
}

fn dump_v1(fname: &str, encoded_buf: Bytes) {
    let container: polio::PolicyContainer = polio::PolicyContainer::decode(encoded_buf)
        .expect("failed to decode binary (v1) policy file");

    let (current_version, version_mismatch) = {
        let (major, minor, patch) = get_compiler_version();
        (
            format!("{}.{}.{}", major, minor, patch),
            container.version_major != major
                || container.version_minor != minor
                || container.version_patch != patch,
        )
    };

    println!("              file: {}", fname.yellow());
    print!(
        "  compiler_version: {}.{}.{}",
        format!("{}", container.version_major).yellow(),
        format!("{}", container.version_minor).yellow(),
        format!("{}", container.version_patch).yellow()
    );
    if version_mismatch {
        println!(" (current is {})", current_version.red());
    } else {
        println!();
    }
    println!("       policy_date: {}", container.policy_date.yellow());
    println!(
        "    policy_version: {}",
        format!("{}", container.policy_version).yellow()
    );
    println!("   policy_revision: {}", container.policy_revision.yellow());
    println!("   policy_metadata: {}", container.policy_metadata.yellow());
    println!(
        "         signature: {}",
        if container.signature.is_empty() {
            "none".red()
        } else {
            "yes (not checked)".yellow()
        }
    );
    println!();

    let encoded_buf = Bytes::from(container.policy);
    let pol: polio::Policy = polio::Policy::decode(encoded_buf).expect("failed to decode policy");

    print!(
        "       connection rules: {:>3}",
        format!("{}", pol.connects.len()).yellow()
    );
    println!(
        "      communication policies: {:>3}",
        format!("{}", pol.policies.len()).yellow()
    );
    print!(
        "               services: {:>3}",
        format!("{}", pol.services.len()).yellow()
    );
    println!(
        "                  procedures: {:>3}",
        format!("{}", pol.procs.len()).yellow()
    );
    print!(
        "                  links: {:>3}",
        format!("{}", pol.links.len()).yellow()
    );
    println!(
        "                certificates: {:>3}",
        format!("{}", pol.certificates.len()).yellow()
    );
    print!(
        "         attribute keys: {:>3}",
        format!("{}", pol.attr_key_index.len()).yellow()
    );
    println!(
        "            attribute values: {:>3}",
        format!("{}", pol.attr_val_index.len()).yellow()
    );
    print!(
        " configuration settings: {:>3}",
        format!("{}", pol.config.len()).yellow()
    );
    println!(
        "                 public keys: {:>3}",
        format!("{}", pol.pubkeys.len()).yellow()
    );

    if !pol.connects.is_empty() {
        print_section_hdr("CONNECTS");
        for (i, connect) in pol.connects.iter().enumerate() {
            print!("connect {}", format!("{}", i + 1).yellow());
            if connect.proc != NO_PROC {
                println!("     proc {}", format!("{:03}", connect.proc).yellow());
            } else {
                println!();
            }

            for aexp in &connect.attr_exprs {
                println!(
                    "     {}",
                    attr_exp_to_string(aexp, &pol.attr_key_index, &pol.attr_val_index).yellow()
                );
            }
        }
    }

    if !pol.policies.is_empty() {
        print_section_hdr("COMMUNICATION POLICIES");
        for (i, cp) in pol.policies.iter().enumerate() {
            print!("policy {}", format!("{}", i + 1).yellow());
            if !cp.allow {
                print!(" {}", "DENY".red().bold());
            }
            println!();
            println!("     service_id: {}", cp.service_id.yellow());
            println!("             id: {}", cp.id.yellow());
            println!("          scope: {}", scopes_to_string(&cp.scope).yellow());
            for cond in &cp.cli_conditions {
                println!(
                    "     cond {} {}:",
                    "cli".bold().italic(),
                    format!("{}", cond.id).yellow()
                );
                for aexp in &cond.attr_exprs {
                    println!(
                        "         {} {}",
                        format!("{}", "󰞘").dimmed(),
                        attr_exp_to_string(aexp, &pol.attr_key_index, &pol.attr_val_index).yellow()
                    );
                }
            }
            for cond in &cp.svc_conditions {
                println!(
                    "     cond {} {}:",
                    "svc".bold().italic(),
                    format!("{}", cond.id).yellow()
                );
                for aexp in &cond.attr_exprs {
                    println!(
                        "         {} {}",
                        format!("{}", "󰞘").dimmed(),
                        attr_exp_to_string(aexp, &pol.attr_key_index, &pol.attr_val_index).yellow()
                    );
                }
            }
        }
    }

    if !pol.services.is_empty() {
        print_section_hdr("SERVICES");
        for (i, service) in pol.services.iter().enumerate() {
            println!("service {}", format!("{}", i + 1).yellow());
            println!(
                "          type: {}",
                svct_to_string(service.r#type).yellow()
            );
            println!("          name: {}", service.name.yellow());
            println!("        prefix: {}", service.prefix.yellow());
            println!("        domain: {}", service.domain.yellow());
            if service.query_uri.is_empty() {
                println!("     query_uri: {}", "unsupported".red());
            } else {
                println!("     query_uri: {}", service.query_uri.yellow());
            }
            if service.validate_uri.is_empty() {
                println!("  validate_uri: {}", "unsupported".red());
            } else {
                println!("  validate_uri: {}", service.validate_uri.yellow());
            }
            // auth type services have attributes.
            if service.r#type == polio::SvcT::SvctAuth as i32 {
                if service.attr_map.is_empty() {
                    println!("         attrs: {}", "none".red());
                } else {
                    println!(
                        "         attrs: {}",
                        if service.attr_map.is_empty() {
                            "[]".yellow()
                        } else {
                            "[".yellow()
                        }
                    );
                    for (ts_attr, zattr) in &service.attr_map {
                        println!(
                            "                  {} -> {}",
                            ts_attr.yellow(),
                            zattr.white()
                        );
                    }
                    if !service.attr_map.is_empty() {
                        println!("                {}", "]".yellow());
                    }
                }
                if service.id_attrs.is_empty() {
                    println!("      id_attrs: {}", "none".red());
                } else {
                    println!(
                        "      id_attrs: {}",
                        array_to_string(&service.id_attrs).yellow()
                    );
                }
            }
        }
    }

    if !pol.procs.is_empty() {
        print_section_hdr("PROCEDURES");
        for (i, proc) in pol.procs.iter().enumerate() {
            println!("proc {}", format!("{:03}", i).yellow());
            for (j, instr) in instrs_to_strings(&proc.proc).iter().enumerate() {
                println!(
                    "     {:03}: {}",
                    format!("{:03}", j).dimmed(),
                    instr.yellow()
                );
            }
        }
    }

    if !pol.links.is_empty() {
        print_section_hdr("LINKS");
        for (i, link) in pol.links.iter().enumerate() {
            println!("link {}", format!("{}", i + 1).yellow());
            for term in &link.terms {
                println!(
                    "     source: {}  ->  dest: {}",
                    parse_addr_to_string(&link.source_id).yellow(),
                    parse_addr_to_string(&term.zpr_id).yellow()
                );
                println!(
                    "     @ {}:{}",
                    term.host.yellow(),
                    format!("{}", term.port).yellow()
                );
                println!(
                    "     key: {}",
                    BASE64_STANDARD.encode(term.key.as_slice()).yellow()
                );
                println!(
                    "     cost: {}    ext_auth: {}",
                    format!("{}", term.cost).yellow(),
                    format!("{}", term.ext_auth).yellow()
                );
            }
        }
    }

    if !pol.certificates.is_empty() {
        print_section_hdr("CERTIFICATES");
        for (i, cert) in pol.certificates.iter().enumerate() {
            println!("cert {}", format!("{}", i + 1).yellow());
            println!(
                "     name: {}    ( ID = {} )",
                cert.name.yellow(),
                format!("{}", cert.id).yellow()
            );
            println!("     data:");
            match X509::from_der(&cert.asn1data) {
                Ok(x509cert) => match x509cert.to_text() {
                    Ok(text) => {
                        let text = String::from_utf8_lossy(&text);
                        for line in text.split('\n') {
                            println!("         {}", line.yellow());
                        }
                    }
                    Err(e) => {
                        println!("     !ERR! {}", e);
                    }
                },
                Err(e) => {
                    println!("     !ERR! {}", e);
                }
            }
        }
    }

    if !(pol.attr_key_index.is_empty() && pol.attr_val_index.is_empty()) {
        print_section_hdr("ATTRIBUTES");
        let key_idx_len = pol.attr_key_index.len();
        let val_idx_len = pol.attr_val_index.len();
        println!("       {}{:>33}", "KEYS".bold(), "VALUES".bold());
        for i in 0..key_idx_len.max(val_idx_len) {
            if i < key_idx_len && i < val_idx_len {
                print!(
                    "     {:>3}: {:<24}",
                    format!("{}", i).yellow(),
                    pol.attr_key_index[i].yellow()
                );
                println!(
                    "  {:>3}: {}",
                    format!("{}", i).yellow(),
                    pol.attr_val_index[i].yellow()
                );
            } else if i < key_idx_len {
                println!(
                    "     {:>3}: {:<24}",
                    format!("{}", i).yellow(),
                    pol.attr_key_index[i].yellow()
                );
            } else {
                println!(
                    "{:>36}{:>3}: {}",
                    "",
                    format!("{}", i).yellow(),
                    pol.attr_val_index[i].yellow()
                );
            }
        }
    }

    if !pol.config.is_empty() {
        print_section_hdr("CONFIGURATION SETTINGS");
        for setting in &pol.config {
            println!(
                "     {} = {}",
                config_setting_key_to_string(setting.key).yellow(),
                config_val_to_string(&setting.val).yellow()
            );
        }
    }

    if !pol.pubkeys.is_empty() {
        print_section_hdr("PUBLIC KEYS");
        for (i, pubkey) in pol.pubkeys.iter().enumerate() {
            println!(
                "pubkey {}    CN = {}",
                format!("{}", i + 1).yellow(),
                pubkey.cn.yellow()
            );
            match Rsa::public_key_from_der(&pubkey.keydata) {
                Ok(rsa) => match rsa.public_key_to_pem() {
                    Ok(pem) => {
                        let pem = String::from_utf8_lossy(&pem);
                        for line in pem.split('\n') {
                            println!("     {}", line.yellow());
                        }
                    }
                    Err(e) => {
                        println!("     !ERR! {}", e);
                    }
                },
                Err(e) => {
                    println!("     !ERR! {}", e);
                }
            }
        }
    }
}

fn dump_v2(fname: &str, encoded_buf: Bytes) {
    let container_rdr = capnp::serialize::read_message(
        &mut std::io::Cursor::new(encoded_buf),
        capnp::message::ReaderOptions::new(),
    )
    .expect("failed to decode binary (v2) policy file");

    let container = container_rdr
        .get_root::<policy_capnp::policy_container::Reader>()
        .expect("failed to get capn proto root of policy container");

    let (current_version, version_mismatch) = {
        let (major, minor, patch) = get_compiler_version();
        (
            format!("{}.{}.{}", major, minor, patch),
            container.get_zplc_ver_major() != major
                || container.get_zplc_ver_minor() != minor
                || container.get_zplc_ver_patch() != patch,
        )
    };

    println!("              file: {}", fname.yellow());
    print!(
        "  compiler_version: {}.{}.{}",
        format!("{}", container.get_zplc_ver_major()).yellow(),
        format!("{}", container.get_zplc_ver_minor()).yellow(),
        format!("{}", container.get_zplc_ver_patch()).yellow()
    );
    if version_mismatch {
        println!(" (current is {})", current_version.red());
    } else {
        println!();
    }
    println!(
        "         signature: {}",
        if !container.has_signature() {
            "none".red()
        } else {
            "yes (not checked)".yellow()
        }
    );
    println!();

    if !container.has_policy() {
        println!("error: {}", "No policy".red().bold());
        return;
    }

    let policy_bytes = container.get_policy().unwrap();

    let policy_rdr = capnp::serialize::read_message(
        &mut std::io::Cursor::new(policy_bytes),
        capnp::message::ReaderOptions::new(),
    )
    .expect("failed to decode binary (v2) policy component");

    let policy = policy_rdr
        .get_root::<policy_capnp::policy::Reader>()
        .expect("failed to get capn proto root of policy");

    println!(
        "       policy_date: {}",
        policy.get_created().unwrap().to_str().unwrap().yellow()
    );
    println!(
        "    policy_version: {}",
        format!("{}", policy.get_version()).yellow()
    );
    println!(
        "   policy_metadata: {}",
        policy.get_metadata().unwrap().to_str().unwrap().yellow()
    );
    if policy.has_com_policies() {
        print_section_hdr("COMMUNICATION POLICIES");
        for (i, cp) in policy.get_com_policies().unwrap().iter().enumerate() {
            print!("policy {}", format!("{}", i + 1).yellow());
            if !cp.get_allow() {
                print!(" {}", "DENY".red().bold());
            }
            println!();
            println!(
                "     service_id: {}",
                cp.get_service_id().unwrap().to_str().unwrap().yellow()
            );
            println!(
                "             id: {}",
                cp.get_id().unwrap().to_str().unwrap().yellow()
            );
            println!(
                "          scope: {}",
                scopes_v2_to_string(&cp.get_scope().unwrap()).yellow()
            );
            if cp.has_client_conds() {
                for cond in cp.get_client_conds().unwrap() {
                    println!("     cond {} :", "cli".bold().italic());
                    println!(
                        "         {} {}",
                        format!("{}", "󰞘").dimmed(),
                        attr_exp_v2_to_string(&cond).yellow()
                    );
                }
            }
            if cp.has_service_conds() {
                for cond in cp.get_service_conds().unwrap() {
                    println!("     cond {} :", "svc".bold().italic());
                    println!(
                        "         {} {}",
                        format!("{}", "󰞘").dimmed(),
                        attr_exp_v2_to_string(&cond).yellow()
                    );
                }
            }
        }
    }
}

fn scopes_v2_to_string<'a>(
    scopes: &::capnp::struct_list::Reader<'a, crate::policy_capnp::scope::Owned>,
) -> String {
    let mut scope_strings = Vec::new();

    for scope in scopes.iter() {
        let mut scope_string = String::new();
        let prot_num = scope.get_protocol();
        match TryInto::<IanaProtocol>::try_into(prot_num as u32) {
            Ok(proto) => scope_string.push_str(&proto.to_string()),
            Err(_) => {
                scope_string.push_str(&format!("!INVALID_PROTOCOL<{}>!", scope.get_protocol()));
            }
        };

        match scope.which() {
            Ok(policy_capnp::scope::Port(pnum)) => {
                scope_string.push_str(&format!(" port {}", pnum.get_port_num()));
            }
            Ok(policy_capnp::scope::PortRange(pr)) => {
                scope_string.push_str(&format!(" ports {}-{}", pr.get_low(), pr.get_high()));
            }
            Err(::capnp::NotInSchema(_)) => {
                scope_string.push_str(" (no ports)");
            }
        }

        scope_strings.push(scope_string);
    }

    scope_strings.join(", ")
}

fn attr_exp_v2_to_string(exp: &policy_capnp::attr_expr::Reader) -> String {
    let mut s = String::new();
    s.push_str(&exp.get_key().unwrap().to_str().unwrap());
    let opstr = match exp.get_op().unwrap() {
        policy_capnp::AttrOp::Eq => "EQ",
        policy_capnp::AttrOp::Ne => "NE",
        policy_capnp::AttrOp::Has => "HAS",
        policy_capnp::AttrOp::Excludes => "EXCLUDES",
    };
    s.push_str(&format!(" {} ", opstr));
    if exp.has_value() {
        let vals = exp.get_value().unwrap();
        if vals.len() > 1 {
            s.push_str("[");
            s.push_str(
                &vals
                    .iter()
                    .map(|v| v.unwrap().to_str().unwrap())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            s.push_str("]");
        } else {
            s.push_str(&vals.get(0).unwrap().to_str().unwrap());
        }
    } else {
        s.push_str("(no value)")
    }
    s
}

fn print_section_hdr(title: &str) {
    println!();
    println!(
        "{}{}{} {}",
        String::from("═").red(),
        String::from("═").white(),
        String::from("═").blue(),
        title.green().bold()
    );
}

fn config_setting_key_to_string(key: u32) -> String {
    match key {
        zpl::CONFIG_KEY_MAX_VISA_LIFETIME => String::from("max_visa_lifetime"),
        _ => format!("key #{}", key),
    }
}

fn config_val_to_string(optval: &Option<polio::config_setting::Val>) -> String {
    match optval {
        Some(polio::config_setting::Val::Sv(s)) => s.clone(),
        Some(polio::config_setting::Val::U32v(n)) => format!("{}", n),
        Some(polio::config_setting::Val::U64v(n)) => format!("{}", n),
        Some(polio::config_setting::Val::Bv(b)) => format!("{}", b),
        None => String::from("null"),
    }
}

fn parse_addr_to_string(addr_bytes: &[u8]) -> String {
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

fn instrs_to_strings(instrs: &[polio::Instruction]) -> Vec<String> {
    instrs.iter().map(instr_to_string).collect::<Vec<String>>()
}

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

fn opcode_to_string(opcode: i32) -> String {
    String::from(match polio::OpCodeT::try_from(opcode) {
        Ok(t) => t.as_str_name(),
        Err(_) => "!ERR!",
    })
}

fn flagt_to_string(flag: i32) -> String {
    String::from(match polio::FlagT::try_from(flag) {
        Ok(f) => f.as_str_name(),
        Err(_) => "!ERR!",
    })
}

fn svct_to_string(svct: i32) -> String {
    String::from(match polio::SvcT::try_from(svct) {
        Ok(st) => st.as_str_name(),
        Err(_) => "!ERR!",
    })
}

fn scopes_to_string(scopes: &[polio::Scope]) -> String {
    scopes
        .iter()
        .map(scope_to_string)
        .collect::<Vec<String>>()
        .join(", ")
}

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

fn attr_exp_to_string(exp: &polio::AttrExpr, keys: &[String], values: &[String]) -> String {
    let mut s = String::new();
    s.push_str(&keys[exp.key as usize]);
    s.push_str(&format!(" {} ", attr_opt_t_to_string(exp.op)));
    s.push_str(&values[exp.val as usize]);
    s
}

fn attr_opt_t_to_string(opval: i32) -> String {
    String::from(match polio::AttrOpT::try_from(opval) {
        Ok(o) => o.as_str_name(),
        Err(_) => "!ERR!",
    })
}

fn array_to_string(arr: &[String]) -> String {
    if arr.is_empty() {
        return String::from("[]");
    }
    let mut s = String::new();
    s.push('[');
    s.push_str(&arr.join(", "));
    s.push(']');
    s
}
