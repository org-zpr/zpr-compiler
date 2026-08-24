use bytes::Bytes;
use std::env;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zplc::compilation::{CompilationBuilder, OutputFormat};
use zplc::dumpv2::dump_v2;
use zpr::policy::v1 as policy_capnp;
use zpr::policy_types::TrustedService;

fn get_zpl_dir() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir).join("test-data")
}

struct TempDir {
    path: PathBuf,
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).expect("failed to remove zpc temp dir");
    }
}

impl TempDir {
    fn new(name_hint: &str) -> Self {
        let mut temp_dir = env::temp_dir();
        temp_dir.push(format!(
            "zpl-test-{}-{}-{}",
            name_hint,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));
        std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir for zpc output");
        TempDir { path: temp_dir }
    }
}

#[test]
fn can_parse_rfc_examples() {
    let zpl_dir = get_zpl_dir();
    let config_file = zpl_dir.join("config.zplc");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list zpl test directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            // And must start with "rfc"
            if let Some(fstem) = path.file_stem() {
                if let Some(fstem_str) = fstem.to_str() {
                    if !fstem_str.starts_with("rfc") {
                        continue;
                    }
                }
            }
            for outfmt in &[OutputFormat::V2] {
                let cb = CompilationBuilder::new(path.clone())
                    .verbose(true)
                    .parse_only(true)
                    .output_format(*outfmt)
                    .config(&config_file);
                let mut comp = cb.build();
                match comp.compile() {
                    Ok(_warnings) => println!("{:?}: compiled to {outfmt:?} ok", fent.path()),
                    Err(e) => {
                        println!("error: {}", e);
                        panic!("failed to compile (format {outfmt:?}) {:?}", fent.path());
                    }
                }
            }
        }
    }
}

#[test]
fn can_compile_m3_policies() {
    let zpl_dir = get_zpl_dir();
    let temp_dir = TempDir::new("m3");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list M3 policy directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            // Must start with "m3-"
            if let Some(fstem) = path.file_stem() {
                if let Some(fstem_str) = fstem.to_str() {
                    if !fstem_str.starts_with("m3-") {
                        continue;
                    }
                }
            }
            for outfmt in &[OutputFormat::V2] {
                let cb = CompilationBuilder::new(path.clone())
                    .verbose(true)
                    .output_format(*outfmt)
                    .output_directory(&temp_dir.path);
                let mut comp = cb.build();
                match comp.compile() {
                    Ok(_warnings) => println!("{:?}: compiled to {outfmt:?} ok", fent.path()),
                    Err(e) => {
                        println!("error: {}", e);
                        panic!("failed to compile (format {outfmt:?}) {:?}", fent.path());
                    }
                }
            }
        }
    }
}

// Make sure we can still compile the policies in the
// integration-test. Note that this does not try to compile
// with the IPv6 config used there.
#[test]
fn can_compile_integtest_policies() {
    let zpl_dir = get_zpl_dir();
    let temp_dir = TempDir::new("integtest");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list integration-test policy directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            // Must start with "integ-"
            if let Some(fstem) = path.file_stem() {
                if let Some(fstem_str) = fstem.to_str() {
                    if !fstem_str.starts_with("m3") {
                        continue;
                    }
                }
            }
            for outfmt in &[OutputFormat::V2] {
                let cb = CompilationBuilder::new(path.clone())
                    .verbose(true)
                    .output_format(*outfmt)
                    .output_directory(&temp_dir.path);
                let mut comp = cb.build();
                match comp.compile() {
                    Ok(_warnings) => println!("{:?}: compiled to {outfmt:?} ok", fent.path()),
                    Err(e) => {
                        println!("error: {}", e);
                        panic!("failed to compile (format {outfmt:?}) {:?}", fent.path());
                    }
                }
            }
        }
    }
}

// Try other misc tests.
#[test]
fn can_compile_misc_test_policies() {
    let zpl_dir = get_zpl_dir();
    let temp_dir = TempDir::new("misctest");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list integration-test policy directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            // Must start with "test-"
            if let Some(fstem) = path.file_stem() {
                if let Some(fstem_str) = fstem.to_str() {
                    if !fstem_str.starts_with("test-") {
                        continue;
                    }
                }
            }

            for outfmt in &[OutputFormat::V2] {
                let cb = CompilationBuilder::new(path.clone())
                    .verbose(true)
                    .output_format(*outfmt)
                    .output_directory(&temp_dir.path);
                let mut comp = cb.build();
                match comp.compile() {
                    Ok(_warnings) => {
                        println!("{:?}: compiled ok", fent.path());
                        // Ok now try to dump it.
                        let encoded = std::fs::read(&comp.output_file)
                            .expect("failed to read binary policy file");
                        let encoded_buf = Bytes::from(encoded);
                        match outfmt {
                            OutputFormat::V2 => {
                                dump_v2(&comp.output_file.to_string_lossy(), encoded_buf);
                            }
                            _ => panic!("unsupported output format for dump test"),
                        }
                        println!("{:?}: dumped ok", fent.path());
                    }
                    Err(e) => {
                        println!("error: {}", e);
                        panic!("failed to compile {:?}", fent.path());
                    }
                }
            }
        }
    }
}

// ---- issue #138: `file` trusted services — end-to-end + regression ----

/// Compile `<stem>.zpl` (with its companion `<stem>.zplc`) to a V2 policy and return the inner
/// policy bytes (already unwrapped from the container).
fn compile_policy_bytes(stem: &str, temp: &TempDir) -> Vec<u8> {
    let path = get_zpl_dir().join(format!("{stem}.zpl"));
    let cb = CompilationBuilder::new(path)
        .output_format(OutputFormat::V2)
        .output_directory(&temp.path);
    let mut comp = cb.build();
    comp.compile()
        .unwrap_or_else(|e| panic!("failed to compile {stem}.zpl: {e}"));
    let encoded = std::fs::read(&comp.output_file).expect("read binary policy");
    let container_rdr = capnp::serialize::read_message(
        &mut Cursor::new(encoded),
        capnp::message::ReaderOptions::new(),
    )
    .expect("decode container");
    let container = container_rdr
        .get_root::<policy_capnp::policy_container::Reader>()
        .expect("container root");
    container.get_policy().expect("policy bytes").to_vec()
}

/// Total endpoints across every join-policy Service with the given id, asserting each such
/// Service is `Trusted(expected_api)`.
fn trusted_service_endpoint_count(
    policy: &policy_capnp::policy::Reader,
    id: &str,
    expected_api: &str,
) -> usize {
    let mut count = 0usize;
    for jp in policy.get_join_policies().unwrap().iter() {
        let provides = match jp.get_provides() {
            Ok(p) => p,
            Err(_) => continue,
        };
        for s in provides.iter() {
            if s.get_id().unwrap().to_str().unwrap() == id {
                match s.get_kind().which().unwrap() {
                    policy_capnp::service::kind::Which::Trusted(n) => {
                        assert_eq!(n.unwrap().to_str().unwrap(), expected_api);
                    }
                    _ => panic!("service {id} must be Trusted({expected_api})"),
                }
                count += s.get_endpoints().unwrap().len() as usize;
            }
        }
    }
    count
}

fn decode_records(policy: &policy_capnp::policy::Reader) -> Vec<TrustedService> {
    policy
        .get_trusted_services()
        .unwrap()
        .iter()
        .map(|r| TrustedService::try_from(r).expect("decode trusted service record"))
        .collect()
}

fn mappings(ts: &TrustedService) -> Vec<(&str, &str)> {
    ts.returns_attrs
        .iter()
        .map(|m| (m.service_attr_key.as_str(), m.zpr_attr_spec.as_str()))
        .collect()
}

#[test]
fn test_file_trusted_service_end_to_end() {
    let temp = TempDir::new("file-e2e");
    let pbytes = compile_policy_bytes("test-file", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    // --- trustedServices: deterministic order, bas + attrfile once each ---
    assert!(
        policy.has_trusted_services(),
        "policy must have trustedServices"
    );
    let records = decode_records(&policy);
    let ids: Vec<&str> = records.iter().map(|r| r.service_id.as_str()).collect();
    assert_eq!(ids, vec!["attrfile", "bas"]);

    // attrfile: expiration 3600, TOML-ordered mappings, empty identity.
    let attrfile = records.iter().find(|r| r.service_id == "attrfile").unwrap();
    assert_eq!(attrfile.expiration_seconds, 3600);
    assert!(attrfile.identity_attrs.is_empty());
    assert_eq!(
        mappings(attrfile),
        vec![("hair_color", "user.hair_color"), ("lazy", "#user.lazy")]
    );

    // bas validation/2 record retained (default expiration + identity preserved).
    let bas = records.iter().find(|r| r.service_id == "bas").unwrap();
    assert_eq!(bas.expiration_seconds, 0);
    assert_eq!(bas.identity_attrs, vec!["bas_id".to_string()]);

    // --- attrfile join Service: Trusted("file"), zero endpoints, selected by cn = vs.zpr ---
    let mut attrfile_svc_found = false;
    for jp in policy.get_join_policies().unwrap().iter() {
        let provides = match jp.get_provides() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let svc = match provides
            .iter()
            .find(|s| s.get_id().unwrap().to_str().unwrap() == "attrfile")
        {
            Some(s) => s,
            None => continue,
        };
        attrfile_svc_found = true;

        // The join policy is selected by exactly device.zpr.adapter.cn EQ vs.zpr.
        let match_exprs = jp.get_match().unwrap();
        assert_eq!(match_exprs.len(), 1);
        let e = match_exprs.get(0);
        assert_eq!(
            e.get_key().unwrap().to_str().unwrap(),
            "device.zpr.adapter.cn"
        );
        assert!(matches!(e.get_op().unwrap(), policy_capnp::AttrOp::Eq));
        let vals: Vec<&str> = e
            .get_value()
            .unwrap()
            .iter()
            .map(|v| v.unwrap().to_str().unwrap())
            .collect();
        assert_eq!(vals, vec!["vs.zpr"]);

        // The service itself is Trusted("file") with zero endpoints.
        match svc.get_kind().which().unwrap() {
            policy_capnp::service::kind::Which::Trusted(n) => {
                assert_eq!(n.unwrap().to_str().unwrap(), "file")
            }
            _ => panic!("attrfile must be Trusted(file)"),
        }
        assert_eq!(
            svc.get_endpoints().unwrap().len(),
            0,
            "file service must have zero endpoints"
        );
    }
    assert!(attrfile_svc_found, "attrfile join Service not found");

    // --- no communication policy for the file service ---
    if policy.has_com_policies() {
        for cp in policy.get_com_policies().unwrap().iter() {
            assert_ne!(
                cp.get_service_id().unwrap().to_str().unwrap(),
                "attrfile",
                "file service must have no communication policy"
            );
        }
    }

    // --- validation/2 (bas) service unchanged: retains its real endpoint ---
    assert!(
        trusted_service_endpoint_count(&policy, "bas", "validation/2") > 0,
        "validation/2 service must retain its endpoint"
    );
}

#[test]
fn test_validation2_regression() {
    // test-bas is validation/2-only; the sole new artifact is the `bas` trustedServices record.
    // Its join/communication policies must be unchanged by the feature.
    let temp = TempDir::new("val2-regression");
    let pbytes = compile_policy_bytes("test-bas", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    // Exactly one record — the validation/2 `bas` service — with its mappings intact.
    let records = decode_records(&policy);
    let ids: Vec<&str> = records.iter().map(|r| r.service_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["bas"],
        "only the validation/2 record should be emitted"
    );
    let bas = &records[0];
    assert_eq!(bas.expiration_seconds, 0);
    assert_eq!(bas.identity_attrs, vec!["bas_id".to_string()]);
    assert_eq!(
        mappings(bas),
        vec![
            ("tint", "device.tint"),
            ("color", "user.color"),
            ("government", "#user.government"),
            ("govpc", "#device.government"),
            ("clearance", "user.clearance"),
            ("classified", "#service.classified"),
            ("roles", "user.role{}"),
            ("bas_id", "user.bas_id"),
        ]
    );

    // Join policy for bas still carries its real validation/2 endpoint.
    assert!(
        trusted_service_endpoint_count(&policy, "bas", "validation/2") > 0,
        "validation/2 endpoint missing"
    );

    // Communication policies are still emitted (join/comm behavior unchanged).
    assert!(policy.has_com_policies());
    assert!(policy.get_com_policies().unwrap().len() > 0);
}

// ---- deterministic bin2 ordering ----

/// One attribute expression as (key, op, values).
type AttrTuple = (String, String, Vec<String>);

/// Order-preserving structural snapshot of every policy collection that must be
/// deterministically ordered. Bytes can't be compared instead: `created`, `version` and
/// `metadata` are wall-clock derived.
#[derive(Debug, PartialEq)]
struct OrderSnapshot {
    /// (service_id, zpl, client conds, service conds)
    com_policies: Vec<(String, String, Vec<AttrTuple>, Vec<AttrTuple>)>,
    /// (conditions, provided service ids)
    join_policies: Vec<(Vec<AttrTuple>, Vec<String>)>,
    keys: Vec<String>,
    /// (link_id, attributes)
    topology: Vec<(String, Vec<AttrTuple>)>,
    trusted_services: Vec<String>,
}

fn attr_tuples(list: capnp::struct_list::Reader<policy_capnp::attr_expr::Owned>) -> Vec<AttrTuple> {
    list.iter()
        .map(|e| {
            (
                e.get_key().unwrap().to_str().unwrap().to_string(),
                format!("{:?}", e.get_op().unwrap()),
                e.get_value()
                    .unwrap()
                    .iter()
                    .map(|v| v.unwrap().to_str().unwrap().to_string())
                    .collect(),
            )
        })
        .collect()
}

/// The same ordering key `JPKey` uses: op lowercased, values sorted, tuples key-sorted.
fn jp_sort_key(conds: &[AttrTuple]) -> Vec<AttrTuple> {
    let mut k: Vec<AttrTuple> = conds
        .iter()
        .map(|(key, op, vals)| {
            let mut vals = vals.clone();
            vals.sort();
            (key.clone(), op.to_lowercase(), vals)
        })
        .collect();
    k.sort();
    k
}

fn snapshot(pbytes: &[u8]) -> OrderSnapshot {
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes),
        capnp::message::ReaderOptions::new(),
    )
    .expect("decode policy");
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    let com_policies = policy
        .get_com_policies()
        .unwrap()
        .iter()
        .map(|cp| {
            (
                cp.get_service_id().unwrap().to_str().unwrap().to_string(),
                cp.get_zpl().unwrap().to_str().unwrap().to_string(),
                attr_tuples(cp.get_client_conds().unwrap()),
                attr_tuples(cp.get_service_conds().unwrap()),
            )
        })
        .collect();

    let join_policies = policy
        .get_join_policies()
        .unwrap()
        .iter()
        .map(|jp| {
            let provides = jp
                .get_provides()
                .map(|ps| {
                    ps.iter()
                        .map(|s| s.get_id().unwrap().to_str().unwrap().to_string())
                        .collect()
                })
                .unwrap_or_default();
            (attr_tuples(jp.get_match().unwrap()), provides)
        })
        .collect();

    let keys = policy
        .get_keys()
        .unwrap()
        .iter()
        .map(|k| k.get_id().unwrap().to_str().unwrap().to_string())
        .collect();

    let topology = policy
        .get_topology()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p.get_link_id().unwrap().to_str().unwrap().to_string(),
                attr_tuples(p.get_attrs().unwrap()),
            )
        })
        .collect();

    let trusted_services = policy
        .get_trusted_services()
        .unwrap()
        .iter()
        .map(|ts| ts.get_service_id().unwrap().to_str().unwrap().to_string())
        .collect();

    OrderSnapshot {
        com_policies,
        join_policies,
        keys,
        topology,
        trusted_services,
    }
}

fn assert_sorted<T: Ord + std::fmt::Debug + Clone>(what: &str, items: &[T]) {
    let mut sorted = items.to_vec();
    sorted.sort();
    assert_eq!(sorted, items, "{what} must be sorted");
}

#[test]
fn test_bin2_ordering_is_deterministic() {
    // Distinct hints: TempDir paths are (hint, pid, seconds), so same-hint dirs alias.
    let temp_a = TempDir::new("ordering-a");
    let temp_b = TempDir::new("ordering-b");
    let snap_a = snapshot(&compile_policy_bytes("test-ordering", &temp_a));
    let snap_b = snapshot(&compile_policy_bytes("test-ordering", &temp_b));
    assert_eq!(
        snap_a, snap_b,
        "recompiling the same input must not reorder"
    );

    let snap = snap_a;

    // Com policies: grouped by service_id ascending, attribute lists key-sorted.
    assert_sorted(
        "com policy service ids",
        &snap
            .com_policies
            .iter()
            .map(|(id, ..)| id.clone())
            .collect::<Vec<_>>(),
    );
    for (id, _zpl, cli, svc) in &snap.com_policies {
        assert_sorted(
            &format!("{id} client cond keys"),
            &cli.iter().map(|(k, ..)| k.clone()).collect::<Vec<_>>(),
        );
        assert_sorted(
            &format!("{id} service cond keys"),
            &svc.iter().map(|(k, ..)| k.clone()).collect::<Vec<_>>(),
        );
    }

    // Within a service, ZPL source order survives: `never` first, then the allows.
    let db1: Vec<&str> = snap
        .com_policies
        .iter()
        .filter(|(id, ..)| id == "database#1")
        .map(|(_, zpl, ..)| zpl.as_str())
        .collect();
    assert_eq!(
        db1,
        vec![
            "(line 9) never allow color:red employees to access classified databases",
            "(line 10) allow lazy, color:green employees to access classified databases on tint:sales devices",
            "(line 11) allow clearance:classified government users to access classified services",
        ]
    );

    // Join policies: outer order follows the full structured condition key; inner lists
    // key-sorted; provides sorted by service id.
    assert_sorted(
        "join policy condition keys",
        &snap
            .join_policies
            .iter()
            .map(|(conds, _)| jp_sort_key(conds))
            .collect::<Vec<_>>(),
    );
    for (conds, provides) in &snap.join_policies {
        assert_sorted(
            "join condition keys",
            &conds.iter().map(|(k, ..)| k.clone()).collect::<Vec<_>>(),
        );
        assert_sorted("join policy provides", provides);
    }

    // Keys, topology (including per-link attributes) and trusted services.
    assert_sorted("bootstrap keys", &snap.keys);
    assert_sorted(
        "topology link ids",
        &snap
            .topology
            .iter()
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>(),
    );
    for (link_id, attrs) in &snap.topology {
        assert_sorted(
            &format!("{link_id} attribute keys"),
            &attrs.iter().map(|(k, ..)| k.clone()).collect::<Vec<_>>(),
        );
    }
    assert_sorted("trusted services", &snap.trusted_services);

    // Sanity: the fixture actually exercises every collection.
    assert!(
        snap.keys.len() >= 2,
        "fixture needs multiple bootstrap keys"
    );
    assert!(snap.topology.len() >= 2, "fixture needs multiple links");
    assert!(
        snap.trusted_services.len() >= 2,
        "fixture needs multiple trusted services"
    );
    assert_eq!(
        db1.len(),
        3,
        "fixture needs a suffixed service with 3 rules"
    );
}

#[test]
fn test_tag_conditions_one_key_per_tag() {
    // Each tag compiles to its own `<domain>.zpr.tag.<name>` key with a valueless HAS
    // (presence check). Multiple tags on one statement must not clobber each other.
    //
    // Previously we mapped tags to <domain>.zpr.tag so tags in the same domain
    // clobbered each other.
    let temp = TempDir::new("tag-encoding");
    let pbytes = compile_policy_bytes("test-tag", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    let mut allow_keys: Option<Vec<String>> = None;
    let mut deny_keys: Option<Vec<String>> = None;
    for cp in policy.get_com_policies().unwrap().iter() {
        if cp.get_service_id().unwrap().to_str().unwrap() != "database" {
            continue;
        }
        let mut keys = Vec::new();
        for cond in cp.get_client_conds().unwrap().iter() {
            let key = cond.get_key().unwrap().to_str().unwrap().to_string();
            assert!(
                matches!(cond.get_op().unwrap(), policy_capnp::AttrOp::Has),
                "tag condition {key} must be HAS"
            );
            assert_eq!(
                cond.get_value().unwrap().len(),
                0,
                "tag condition {key} must be valueless (presence check)"
            );
            keys.push(key);
        }
        keys.sort();
        if cp.get_allow() {
            allow_keys = Some(keys);
        } else {
            deny_keys = Some(keys);
        }
    }

    assert_eq!(
        allow_keys.expect("allow policy for database not found"),
        vec!["user.zpr.tag.nerd", "user.zpr.tag.redhead"]
    );
    assert_eq!(
        deny_keys.expect("never policy for database not found"),
        vec!["user.zpr.tag.baldy", "user.zpr.tag.stud"]
    );
}

#[test]
fn test_link_conditions_end_to_end() {
    // An "over <link-clause>" constrains the links of the communication path.
    // The compiler records those constraints in `CPolicy.linkConds`; enforcement
    // is the visa service's job and is deliberately out of scope here.
    let temp = TempDir::new("link-over");
    let pbytes = compile_policy_bytes("test-link-over", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    // Collect (client-condition keys, link-condition tuples) per database policy.
    let mut allow_with_links: Option<Vec<(String, Vec<String>)>> = None;
    let mut deny_with_links: Option<Vec<(String, Vec<String>)>> = None;
    let mut saw_policy_without_links = false;

    for cp in policy.get_com_policies().unwrap().iter() {
        if cp.get_service_id().unwrap().to_str().unwrap() != "database" {
            continue;
        }
        let mut link_conds = Vec::new();
        for cond in cp.get_link_conds().unwrap().iter() {
            let key = cond.get_key().unwrap().to_str().unwrap().to_string();
            let vals: Vec<String> = cond
                .get_value()
                .unwrap()
                .iter()
                .map(|v| v.unwrap().to_str().unwrap().to_string())
                .collect();
            link_conds.push((key, vals));
        }
        link_conds.sort();

        let cli_keys: Vec<String> = cp
            .get_client_conds()
            .unwrap()
            .iter()
            .map(|c| c.get_key().unwrap().to_str().unwrap().to_string())
            .collect();

        if link_conds.is_empty() {
            // This is the "nerd" statement, which has no over clause.
            assert!(
                cli_keys.iter().any(|k| k.contains("nerd")),
                "unexpected policy with no link conditions: {cli_keys:?}"
            );
            saw_policy_without_links = true;
        } else if cp.get_allow() {
            allow_with_links = Some(link_conds);
        } else {
            deny_with_links = Some(link_conds);
        }
    }

    // "over secure, location:usa links" -> a valueless tag plus a key/value pair,
    // both in the link domain.
    let allow_conds = allow_with_links.expect("allow policy with link conditions not found");
    assert_eq!(
        allow_conds,
        vec![
            ("link.location".to_string(), vec!["usa".to_string()]),
            ("link.zpr.tag.secure".to_string(), vec![]),
        ]
    );

    // "never allow ... over foreign links" must carry its link condition too.
    let deny_conds = deny_with_links.expect("never policy with link conditions not found");
    assert_eq!(
        deny_conds,
        vec![("link.zpr.tag.foreign".to_string(), vec![])]
    );

    assert!(
        saw_policy_without_links,
        "expected a policy with no over clause to have empty linkConds"
    );

    // Every emitted link condition must actually be satisfiable by a link in the
    // compiled topology. This is the property that matters: the ZPL side and the
    // ZPLC side have to agree on the attribute encoding, otherwise a `never allow`
    // with an over clause would fail open once the visa service enforces link rules.
    let mut topo_keys: Vec<String> = Vec::new();
    for peering in policy.get_topology().unwrap().iter() {
        for attr in peering.get_attrs().unwrap().iter() {
            topo_keys.push(attr.get_key().unwrap().to_str().unwrap().to_string());
        }
    }
    topo_keys.sort();
    topo_keys.dedup();

    // The tag on the link (`["#secure", ""]` in the zplc) must encode identically to
    // the tag written in ZPL (`over secure links`).
    assert!(
        topo_keys.contains(&"link.zpr.tag.secure".to_string()),
        "configured link tag not encoded as link.zpr.tag.secure: {topo_keys:?}"
    );
    assert!(
        topo_keys.contains(&"link.zpr.tag.foreign".to_string()),
        "configured link tag not encoded as link.zpr.tag.foreign: {topo_keys:?}"
    );
    assert!(
        topo_keys.contains(&"link.location".to_string()),
        "configured link key/value attribute missing: {topo_keys:?}"
    );

    for (key, _) in allow_conds.iter().chain(deny_conds.iter()) {
        assert!(
            topo_keys.contains(key),
            "link condition {key} is satisfied by no configured link (topology keys: {topo_keys:?})"
        );
    }
}

#[test]
fn test_over_clause_with_unconfigured_attribute_fails_to_compile() {
    // ZPL and ZPLC are always compiled together, so a link attribute that appears on no
    // configured link means the author wrote a statement that can never match. Fail loudly.
    // Named "bad-" rather than "test-" so the bulk must-compile sweeps skip it.
    let temp = TempDir::new("link-over-bad");
    let path = get_zpl_dir().join("bad-link-over-unsatisfiable.zpl");
    let cb = CompilationBuilder::new(path)
        .output_format(OutputFormat::V2)
        .output_directory(&temp.path);
    let mut comp = cb.build();
    let err = comp
        .compile()
        .expect_err("over clause naming an unconfigured link attribute must not compile");
    let msg = err.to_string();
    assert!(
        msg.contains("not present on any configured link"),
        "unexpected error: {msg}"
    );
    assert!(
        msg.contains("nosuchtag"),
        "error should name the offending attribute: {msg}"
    );
}
