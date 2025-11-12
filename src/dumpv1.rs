use colored::Colorize;
use polio::polio;

use base64::prelude::*;

use bytes::Bytes;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use prost::Message;

use crate::compiler::get_compiler_version;
use crate::dump;
use crate::policybinaryv1::NO_PROC;

pub fn dump_v1(fname: &str, encoded_buf: Bytes) {
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
        dump::print_section_hdr("CONNECTS");
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
                    dump::attr_exp_to_string(aexp, &pol.attr_key_index, &pol.attr_val_index)
                        .yellow()
                );
            }
        }
    }

    if !pol.policies.is_empty() {
        dump::print_section_hdr("COMMUNICATION POLICIES");
        for (i, cp) in pol.policies.iter().enumerate() {
            print!("policy {}", format!("{}", i + 1).yellow());
            if !cp.allow {
                print!(" {}", "DENY".red().bold());
            }
            println!();
            println!("     service_id: {}", cp.service_id.yellow());
            println!("             id: {}", cp.id.yellow());
            println!(
                "          scope: {}",
                dump::scopes_to_string(&cp.scope).yellow()
            );
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
                        dump::attr_exp_to_string(aexp, &pol.attr_key_index, &pol.attr_val_index)
                            .yellow()
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
                        dump::attr_exp_to_string(aexp, &pol.attr_key_index, &pol.attr_val_index)
                            .yellow()
                    );
                }
            }
        }
    }

    if !pol.services.is_empty() {
        dump::print_section_hdr("SERVICES");
        for (i, service) in pol.services.iter().enumerate() {
            println!("service {}", format!("{}", i + 1).yellow());
            println!(
                "          type: {}",
                dump::svct_to_string(service.r#type).yellow()
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
                        dump::array_to_string(&service.id_attrs).yellow()
                    );
                }
            }
        }
    }

    if !pol.procs.is_empty() {
        dump::print_section_hdr("PROCEDURES");
        for (i, proc) in pol.procs.iter().enumerate() {
            println!("proc {}", format!("{:03}", i).yellow());
            for (j, instr) in dump::instrs_to_strings(&proc.proc).iter().enumerate() {
                println!(
                    "     {:03}: {}",
                    format!("{:03}", j).dimmed(),
                    instr.yellow()
                );
            }
        }
    }

    if !pol.links.is_empty() {
        dump::print_section_hdr("LINKS");
        for (i, link) in pol.links.iter().enumerate() {
            println!("link {}", format!("{}", i + 1).yellow());
            for term in &link.terms {
                println!(
                    "     source: {}  ->  dest: {}",
                    dump::parse_addr_to_string(&link.source_id).yellow(),
                    dump::parse_addr_to_string(&term.zpr_id).yellow()
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
        dump::print_section_hdr("CERTIFICATES");
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
        dump::print_section_hdr("ATTRIBUTES");
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
        dump::print_section_hdr("CONFIGURATION SETTINGS");
        for setting in &pol.config {
            println!(
                "     {} = {}",
                dump::config_setting_key_to_string(setting.key).yellow(),
                dump::config_val_to_string(&setting.val).yellow()
            );
        }
    }

    if !pol.pubkeys.is_empty() {
        dump::print_section_hdr("PUBLIC KEYS");
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
