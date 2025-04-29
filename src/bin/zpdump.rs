use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use prost::Message;
use prost::bytes::Bytes;
use zpcsuite::polio::PolicyContainer;
use zpcsuite::polio::Policy;
use zpcsuite::policybuilder::NO_PROC;
use zpcsuite::protocols::IanaProtocol;

use bytes::{Buf, BytesMut, BufMut};


/// ZPL Policy Dumper
///
/// Prints contents of a binary policy file to stdout.
#[derive(Debug, Parser)]
#[command(name = "zpdump")]
#[command(version = "0.2.0", verbatim_doc_comment)]
struct Cli {
    /// Path to the ZPL file.
    #[arg(value_name = "ZPL_FILE")]
    zpl: PathBuf,

    /// Sets extra verbosity.
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let exit_code = 0;
    let cli = Cli::parse();
    println!("{}", "hello from zpdump!".green());

    println!("examining {}", cli.zpl.display());


    let encoded = std::fs::read(cli.zpl).expect("failed to read binary policy file");
    let encoded_buf = bytes::Bytes::from(encoded);
    let container: PolicyContainer = PolicyContainer::decode(encoded_buf).expect("failed to decode binary policy file");

    println!(" container_version: {}", format!("{}", container.container_version).yellow());
    println!("       policy_date: {}", container.policy_date.yellow());
    println!("    policy_version: {}", format!("{}", container.policy_version).yellow());
    println!("   policy_revision: {}", container.policy_revision.yellow());
    println!("   policy_metadata: {}", container.policy_metadata.yellow());
    println!("         signature: {}", if container.signature.is_empty() { "none".red()} else { "yes (not checked)".yellow() });
    println!();

    let encoded_buf = bytes::Bytes::from(container.policy);
    let pol: Policy = Policy::decode(encoded_buf).expect("failed to decode policy");

    println!("         serial_version: {:>3}", format!("{}", pol.serial_version).yellow());
    print!("       connection rules: {:>3}", format!("{}", pol.connects.len()).yellow());
    println!("      communication policies: {:>3}", format!("{}", pol.policies.len()).yellow());
    print!("               services: {:>3}", format!("{}", pol.services.len()).yellow());
    println!("                  procedures: {:>3}", format!("{}", pol.procs.len()).yellow());
    print!("                  links: {:>3}", format!("{}", pol.links.len()).yellow());
    println!("                certificates: {:>3}", format!("{}", pol.certificates.len()).yellow());
    print!("         attribute keys: {:>3}", format!("{}", pol.attr_key_index.len()).yellow());
    println!("            attribute values: {:>3}", format!("{}", pol.attr_val_index.len()).yellow());
    print!(" configuration settings: {:>3}", format!("{}", pol.config.len()).yellow());
    println!("                 public keys: {:>3}", format!("{}", pol.pubkeys.len()).yellow());

    // Connects
    println!();
    println!("=== CONNECTS");
    for (i, connect) in pol.connects.iter().enumerate() {
        print!("connect {}", format!("{}", i+1).yellow());
        if connect.proc != NO_PROC {
            println!("     proc {}", format!("{:03}", connect.proc).yellow());
        } else {
            println!();
        }

        for aexp in &connect.attr_exprs {
            println!("     {}", attr_exp_to_string(aexp, &pol.attr_key_index, &pol.attr_val_index).yellow());
        }
    }

    println!();
    println!("=== COMMUNICATION POLICIES");
    for (i, cp) in pol.policies.iter().enumerate() {
        println!("policy {}", format!("{}", i+1).yellow());
        println!("     service_id: {}", cp.service_id.yellow());
        println!("             id: {}", cp.id.yellow());
        println!("          scope: {}", scopes_to_string(&cp.scope).yellow());
    }

    println!();
    println!("=== SERVICES");

    // and so on

    std::process::exit(exit_code);
}



fn scopes_to_string(scopes: &Vec<zpcsuite::polio::Scope>) -> String {
    scopes.iter()
        .map(|scope| scope_to_string(scope))
        .collect::<Vec<String>>()
        .join(", ")
}

fn scope_to_string(scope: &zpcsuite::polio::Scope) -> String {
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
            zpcsuite::polio::scope::Protarg::Pspec(pslist) => {
                for ps in &pslist.spec {
                    if let Some(psp) = &ps.parg {
                        match psp {
                            zpcsuite::polio::port_spec::Parg::Port(pnum) => {
                                s.push_str(&format!(" {pnum}"));
                            }
                            zpcsuite::polio::port_spec::Parg::Pr(prange) => {
                                s.push_str(&format!(" {}-{}", prange.low, prange.high));
                            }
                        }
                    }
                }
            }
            zpcsuite::polio::scope::Protarg::Icmp(icmp) => {
                match zpcsuite::polio::Icmpt::try_from(icmp.r#type) {
                    Ok(zpcsuite::polio::Icmpt::Unused) => s.push_str(" !UNUSED! "),
                    Ok(zpcsuite::polio::Icmpt::Reqrep) => s.push_str(" REQREP "),
                    Ok(zpcsuite::polio::Icmpt::Once) => s.push_str(" ONCE "),
                    Err(_) => s.push_str(" !ERR! "),
                }
                s.push_str(&format!(" codes:{:?}", icmp.codes));
            }
        }
    }
    s
}




fn attr_exp_to_string(exp: &zpcsuite::polio::AttrExpr, keys: &Vec<String>, values: &Vec<String>) -> String {
    let mut s = String::new();
    s.push_str(&keys[exp.key as usize]);
    s.push_str(&format!(" {} ", attr_opt_t_to_string(exp.op)));
    s.push_str(&values[exp.val as usize]);
    s
}


fn attr_opt_t_to_string(opval: i32) -> String {
    String::from(match zpcsuite::polio::AttrOpT::try_from(opval) {
        Ok(zpcsuite::polio::AttrOpT::Eq) => "=",
        Ok(zpcsuite::polio::AttrOpT::Ne) => "!=",
        Ok(zpcsuite::polio::AttrOpT::Has) => "HAS",
        Ok(zpcsuite::polio::AttrOpT::Excludes) => "EXCL",
        Ok(zpcsuite::polio::AttrOpT::Unused) => "!UNUSED!", // shouldn't happen
        Err(_) => "!ERR!", // shouldn't happen
    })
}