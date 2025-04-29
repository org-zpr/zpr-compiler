use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use prost::Message;
use bytes::Bytes;

use zpcsuite::polio::PolicyContainer;
use zpcsuite::polio::Policy;
use zpcsuite::polio;
use zpcsuite::policybuilder::NO_PROC;
use zpcsuite::protocols::IanaProtocol;




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
    let encoded_buf = Bytes::from(encoded);
    let container: PolicyContainer = PolicyContainer::decode(encoded_buf).expect("failed to decode binary policy file");

    println!(" container_version: {}", format!("{}", container.container_version).yellow());
    println!("       policy_date: {}", container.policy_date.yellow());
    println!("    policy_version: {}", format!("{}", container.policy_version).yellow());
    println!("   policy_revision: {}", container.policy_revision.yellow());
    println!("   policy_metadata: {}", container.policy_metadata.yellow());
    println!("         signature: {}", if container.signature.is_empty() { "none".red()} else { "yes (not checked)".yellow() });
    println!();

    let encoded_buf = Bytes::from(container.policy);
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



fn scopes_to_string(scopes: &Vec<polio::Scope>) -> String {
    scopes.iter()
        .map(|scope| scope_to_string(scope))
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
                    Ok(polio::Icmpt::Unused) => s.push_str(" !UNUSED! "),
                    Ok(polio::Icmpt::Reqrep) => s.push_str(" REQREP "),
                    Ok(polio::Icmpt::Once) => s.push_str(" ONCE "),
                    Err(_) => s.push_str(" !ERR! "),
                }
                s.push_str(&format!(" codes:{:?}", icmp.codes));
            }
        }
    }
    s
}




fn attr_exp_to_string(exp: &polio::AttrExpr, keys: &Vec<String>, values: &Vec<String>) -> String {
    let mut s = String::new();
    s.push_str(&keys[exp.key as usize]);
    s.push_str(&format!(" {} ", attr_opt_t_to_string(exp.op)));
    s.push_str(&values[exp.val as usize]);
    s
}


fn attr_opt_t_to_string(opval: i32) -> String {
    String::from(match polio::AttrOpT::try_from(opval) {
        Ok(polio::AttrOpT::Eq) => "=",
        Ok(polio::AttrOpT::Ne) => "!=",
        Ok(polio::AttrOpT::Has) => "HAS",
        Ok(polio::AttrOpT::Excludes) => "EXCL",
        Ok(polio::AttrOpT::Unused) => "!UNUSED!", // shouldn't happen
        Err(_) => "!ERR!", // shouldn't happen
    })
}