use bytes::Bytes;
use colored::Colorize;
use openssl::rsa::Rsa;
use std::convert::TryInto;
use zpr::policy::v1 as policy_capnp;

use crate::compiler::get_compiler_version;
use crate::dump;
use crate::protocols::IanaProtocol;

pub fn dump_v2(fname: &str, encoded_buf: Bytes) {
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

    if policy.has_join_policies() {
        dump::print_section_hdr("JOIN POLICIES");
        for (i, jp) in policy.get_join_policies().unwrap().iter().enumerate() {
            print!("join {}", format!("{}", i + 1).yellow());
            let svc_count = jp.get_provides().map_or(0, |p| p.len());
            let flag_count = jp.get_flags().map_or(0, |f| f.len());
            print!(
                "  {} service{}",
                svc_count,
                if svc_count == 1 { "" } else { "s" },
            );
            if flag_count > 0 {
                println!(
                    " - flags {}",
                    format!("{:?}", jp.get_flags().unwrap()).magenta()
                );
            } else {
                println!();
            }

            for (_j, match_attr) in jp.get_match().unwrap().iter().enumerate() {
                println!(
                    "         {} {}",
                    format!("{}", "󰞘").dimmed(),
                    attr_exp_v2_to_string(&match_attr).yellow()
                );
            }
            if svc_count > 0 {
                for (j, svc) in jp.get_provides().unwrap().iter().enumerate() {
                    let stype = match svc.get_kind().which().unwrap() {
                        policy_capnp::service::kind::Which::Builtin(_) => "built_in",
                        policy_capnp::service::kind::Which::Auth(_) => "auth",
                        policy_capnp::service::kind::Which::Visa(_) => "visa",
                        policy_capnp::service::kind::Which::Regular(_) => "",
                        policy_capnp::service::kind::Which::Trusted(n) => {
                            let nn = n.unwrap().to_str().unwrap();
                            &format!("trusted ({})", nn)
                        }
                    };

                    println!(
                        "        {} {} {}",
                        format!("{}", j + 1).dimmed(),
                        svc.get_id().unwrap().to_str().unwrap().yellow(),
                        stype.blue()
                    );
                    for (k, ep) in svc.get_endpoints().unwrap().iter().enumerate() {
                        let pname = match IanaProtocol::try_from(ep.get_protocol()) {
                            Ok(p) => p.to_string().green(),
                            Err(_) => format!("protocol({})", ep.get_protocol()).red(),
                        };

                        if k > 0 {
                            print!(" / ");
                        } else {
                            print!("          ");
                        }
                        print!("{}", pname);

                        match ep.which().unwrap() {
                            policy_capnp::endpoint::Which::Port(pg) => {
                                print!("{}", format!("{:?}", pg.get_ports().unwrap()).green());
                            }
                            policy_capnp::endpoint::Which::PortRange(pr) => {
                                print!(
                                    "{}",
                                    format!("[{}-{}]", pr.get_low(), pr.get_high()).green()
                                );
                            }
                        }

                        if let Ok(ft) = ep.get_icmp_flow() {
                            if ft != policy_capnp::IcmpFlowType::Unset {
                                print!(" {}", format!("{:?}", ft).yellow());
                            }
                        }
                    }
                    println!();
                }
            }
            println!();
        }
    }

    if policy.has_com_policies() {
        dump::print_section_hdr("COMMUNICATION POLICIES");
        for (i, cp) in policy.get_com_policies().unwrap().iter().enumerate() {
            print!("policy {}", format!("{}", i + 1).yellow());
            if cp.has_zpl() {
                print!("  {}", cp.get_zpl().unwrap().to_str().unwrap().green());
            } else {
                print!("  {}", "(zpl missing)".red());
            }
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
                    println!("      cond {} :", "cli".bold().italic());
                    println!(
                        "         {} {}",
                        format!("{}", "󰞘").dimmed(),
                        attr_exp_v2_to_string(&cond).yellow()
                    );
                }
            }
            if cp.has_service_conds() {
                for cond in cp.get_service_conds().unwrap() {
                    println!("      cond {} :", "svc".bold().italic());
                    println!(
                        "         {} {}",
                        format!("{}", "󰞘").dimmed(),
                        attr_exp_v2_to_string(&cond).yellow()
                    );
                }
            }
            println!();
        }
    }
    if policy.has_keys() {
        dump::print_section_hdr("KEYS");
        for (i, key) in policy.get_keys().unwrap().iter().enumerate() {
            print!(
                "{} id: {}",
                format!("{:02}", i + 1).dimmed(),
                key.get_id().unwrap().to_str().unwrap().yellow()
            );
            println!(
                "  type: {}",
                match key.get_key_type().unwrap() {
                    policy_capnp::KeyMaterialT::RsaPub => "RSA_PUBLIC".green(),
                }
            );
            let mut allowances = Vec::new();
            let allows = key.get_key_allows().unwrap();
            for allow in allows.iter() {
                allowances.push(format!("+{:?}  ", allow.unwrap()));
            }
            println!("   allows:   {}", allowances.join("\n").yellow());

            print!(
                "   material: {}",
                format!("({} bytes", key.get_key_data().unwrap().len()).dimmed()
            );

            if key.get_key_type().unwrap() != policy_capnp::KeyMaterialT::RsaPub {
                println!("{}", ", omitted)".dimmed());
            } else {
                println!("{}", ")".dimmed());
                match Rsa::public_key_from_der(&key.get_key_data().unwrap()) {
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
}

fn scopes_v2_to_string<'a>(
    scopes: &::capnp::struct_list::Reader<'a, policy_capnp::scope::Owned>,
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
        } else if vals.len() == 1 {
            s.push_str(&vals.get(0).unwrap().to_str().unwrap());
        } else {
            s.push_str("\"\"");
        }
    } else {
        s.push_str("(no value)")
    }
    s
}
