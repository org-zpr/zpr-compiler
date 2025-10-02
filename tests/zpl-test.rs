use bytes::Bytes;
use std::env;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zplc::compilation::{CompilationBuilder, OutputFormat};
use zplc::dump::{dump_v1, dump_v2};

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
            for outfmt in &[OutputFormat::V1, OutputFormat::V2] {
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
            for outfmt in &[OutputFormat::V1, OutputFormat::V2] {
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
            for outfmt in &[OutputFormat::V1, OutputFormat::V2] {
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

            for outfmt in &[OutputFormat::V1, OutputFormat::V2] {
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
                            OutputFormat::V1 => {
                                dump_v1(&comp.output_file.to_string_lossy(), encoded_buf);
                            }
                            OutputFormat::V2 => {
                                dump_v2(&comp.output_file.to_string_lossy(), encoded_buf);
                            }
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
