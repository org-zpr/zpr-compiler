//! Parsers for the `nodes` and `links` TOML sections and their sub-structures.

use std::collections::HashMap;
use std::net::IpAddr;

use toml::Table;

use crate::context::CompilationCtx;
use crate::err_config;
use crate::errors::CompilationError;

use super::{Interface, Link, Node, Resolver, parse_attribute_tuples, parse_provider};

fn require_key(ctx: &str, table: &Table, key: &str) -> Result<(), CompilationError> {
    if !table.contains_key(key) {
        return Err(err_config!("error in {}: missing entry for {}", ctx, key));
    }
    Ok(())
}

fn warn_unknown_node_property(node: &Table, ctx: &CompilationCtx) -> Result<(), CompilationError> {
    for elem in node.keys() {
        match elem.as_str() {
            "provider" => (),
            "zpr_address" => (),
            "substrate_addrs" => (),
            _ => ctx.warn(&format!(
                "unknown property '{elem}' detected while parsing node",
            ))?,
        }
    }

    Ok(())
}

fn warn_unknown_link_property(link: &Table, ctx: &CompilationCtx) -> Result<(), CompilationError> {
    for elem in link.keys() {
        match elem.as_str() {
            "peers" => (),
            "attributes" => (),
            _ => ctx.warn(&format!(
                "unknown property '{elem}' detected while parsing link",
            ))?,
        }
    }
    Ok(())
}

/// Parse a single node table.
pub(super) fn parse_node(
    node_id: &str,
    node: &Table,
    resolver: &Resolver,
    ctx: &CompilationCtx,
) -> Result<Node, CompilationError> {
    warn_unknown_node_property(node, ctx)?;
    require_key(&format!("nodes.{}", node_id), node, "zpr_address")?;
    let zpr_address_str = node["zpr_address"]
        .as_str()
        .ok_or(err_config!("node {} invalid zpr_address", node_id))?
        .to_string();

    let zpr_address = match zpr_address_str.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(e) => {
            // Not an IP address, so try to resolve as a hostname.
            if let Some(ip) = resolver.resolve(&zpr_address_str) {
                ip
            } else {
                return Err(err_config!(
                    "node {} has invalid zpr_address '{}': {}",
                    node_id,
                    zpr_address_str,
                    e
                ));
            }
        }
    };

    let provider = parse_provider(&format!("node {}", node_id), node)?;

    Ok(Node {
        id: node_id.to_string(),
        zpr_address,
        substrate_addrs: None, // filled in later if present
        provider,
    })
}

/// Parses the "link.<LINKID>" table from the toml config.
/// This should include a peers entry (2 element array) and an optional attributes entry.
pub(super) fn parse_link(
    link_id: &str,
    link_tbl: &Table,
    ctx: &CompilationCtx,
    nodes: &HashMap<String, Node>,
) -> Result<Link, CompilationError> {
    warn_unknown_link_property(link_tbl, ctx)?;

    require_key(&format!("links.{}", link_id), link_tbl, "peers")?;
    let peers = link_tbl["peers"]
        .as_array()
        .ok_or(err_config!("link {} peers should be an array", link_id))?;

    if peers.len() != 2 {
        return Err(err_config!("link {} must have exactly two peers", link_id));
    }

    // These all get filled in in the for loop below, or we error out.
    let mut peer_a_id = None;
    let mut peer_a_interface = None;
    let mut peer_b_id = None;
    let mut peer_b_interface = None;

    for (i, peer) in peers.iter().enumerate() {
        let peer_tbl =
            peer.as_table()
                .ok_or(err_config!("link {} peer {} should be a table", link_id, i))?;

        require_key(&format!("links.{}.peers[{}]", link_id, i), peer_tbl, "node")?;
        let node_id = peer_tbl["node"]
            .as_str()
            .ok_or(err_config!(
                "link {} peer {} node should be a string",
                link_id,
                i
            ))?
            .to_string();

        let refnode = nodes.get(&node_id);
        if !refnode.is_some() {
            return Err(err_config!(
                "link {} peer {} references unknown node '{}'",
                link_id,
                i,
                node_id
            ));
        }
        let refnode = refnode.unwrap();

        if refnode.substrate_addrs.is_none() {
            return Err(err_config!(
                "link {} peer {} references node '{}' with no substrate_addrs",
                link_id,
                i,
                node_id
            ));
        }

        let interface = if peer_tbl.contains_key("interface") {
            let iname = peer_tbl["interface"]
                .as_str()
                .ok_or(err_config!(
                    "link {} peer {} interface should be a string",
                    link_id,
                    i
                ))?
                .to_string();
            // Interface name must exist on node.
            if !refnode
                .substrate_addrs
                .as_ref()
                .unwrap()
                .contains_key(&iname)
            {
                return Err(err_config!(
                    "link {} peer {} references interface '{}' which does not exist on node '{}'",
                    link_id,
                    i,
                    iname,
                    node_id
                ));
            }
            Some(iname)
        } else {
            // Interface can be omitted if node has single substreate address.
            if refnode.substrate_addrs.as_ref().unwrap().len() == 1 {
                // Just take the single interface.
                refnode
                    .substrate_addrs
                    .as_ref()
                    .unwrap()
                    .keys()
                    .next()
                    .cloned()
            } else {
                return Err(err_config!(
                    "link {} peer {} missing interface and node '{}' has multiple substrate_addrs",
                    link_id,
                    i,
                    node_id
                ));
            }
        };

        if i == 0 {
            peer_a_id = Some(node_id);
            peer_a_interface = interface;
        } else {
            peer_b_id = Some(node_id);
            peer_b_interface = interface;
        }
    }

    let attrs = match parse_attribute_tuples(&format!("links.{}", link_id), link_tbl, "attributes")?
    {
        Some(attrs) => attrs,
        None => Vec::new(),
    };

    Ok(Link {
        peer_a_id: peer_a_id.unwrap(),
        peer_a_interface: peer_a_interface.unwrap(),
        peer_b_id: peer_b_id.unwrap(),
        peer_b_interface: peer_b_interface.unwrap(),
        attributes: attrs,
    })
}

/// Parse a node substrate addrs table.
pub(super) fn parse_substrate_addrs(
    node_id: &str,
    addrs: &Table,
    _ctx: &CompilationCtx,
) -> Result<HashMap<String, Interface>, CompilationError> {
    let mut substrate_addrs = HashMap::new();
    for (ifname, v) in addrs {
        let iface = parse_interface(
            ifname,
            v.as_str().ok_or(err_config!(
                "node {} substrate_addr {} should be a \"HOST:PORT\" formatted string",
                node_id,
                ifname
            ))?,
        )?;
        substrate_addrs.insert(ifname.to_string(), iface);
    }
    Ok(substrate_addrs)
}

/// Parse the nodes interface entry which is just "HOST:PORT"
fn parse_interface(ifname: &str, netaddr: &str) -> Result<Interface, CompilationError> {
    // Form of `netaddr` is HOST:PORT, host may be a hostname (which may need to be run through the resolver)
    // or an IPv4 or IPv6 address.

    // We'll try to parse as a SocketAddr first (which requires an IP address, not a name)
    //let saddr: std::net::SocketAddr = netaddr.parse();
    match netaddr.parse::<std::net::SocketAddr>() {
        Ok(saddr) => Ok(Interface {
            host: saddr.ip().to_string(),
            port: saddr.port(),
        }),
        Err(_) => {
            // Did not parse as a SocketAddr, so try as "hostname:portnum"
            let parts: Vec<&str> = netaddr.split(':').collect();
            if parts.len() != 2 {
                return Err(err_config!(
                    "interface {} netaddr must be in the form HOST:PORT",
                    ifname
                ));
            }
            let portnum = parts[1].parse::<u16>().map_err(|_| {
                err_config!(
                    "interface {} port number is not a valid: {}",
                    ifname,
                    parts[1]
                )
            })?;
            Ok(Interface {
                host: parts[0].to_string(),
                port: portnum,
            })
        }
    }
}
