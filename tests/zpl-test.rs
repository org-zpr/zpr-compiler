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
fn trusted_service_endpoint_count(policy: &policy_capnp::policy::Reader, id: &str, expected_api: &str) -> usize {
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
    assert!(policy.has_trusted_services(), "policy must have trustedServices");
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
        assert_eq!(e.get_key().unwrap().to_str().unwrap(), "device.zpr.adapter.cn");
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
    assert_eq!(ids, vec!["bas"], "only the validation/2 record should be emitted");
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
