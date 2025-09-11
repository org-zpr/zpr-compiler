use openssl::pkey::Private;
use openssl::rsa::Rsa;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config_api::ConfigApi;
use crate::context::CompilationCtx;
use crate::crypto::{sha256_of_file, sign_pkcs1v15_sha256};
use crate::errors::CompilationError;
use crate::lex::tokenize;
use crate::parser::parse;
use crate::policybinaryv1::{PolicyBinaryV1, PolicyContainerV1};
use crate::policybinaryv2::{PbV2Memory, PolicyBinaryV2, PolicyContainerV2};
use crate::policybuilder::PolicyBuilder;
use crate::policywriter::PolicyContainer;
use crate::weaver::weave;

/// Create one of these with the [CompilationBuilder].
pub struct Compilation {
    pub verbose: bool,
    werror: bool,
    pub source_zpl: PathBuf,
    pub source_config: PathBuf,
    pub output_file: PathBuf,
    pub parse_only: bool,
    private_key: Option<Rsa<Private>>,
    output_format: OutputFormat,
    v2_memory: Option<PbV2Memory>,
}

impl Compilation {
    /// Returns a new [CompilationBuilder] using the passed ZPL source file and
    /// reasonable defaults.
    pub fn builder(source: PathBuf) -> CompilationBuilder {
        CompilationBuilder::new(source)
    }

    /// Create/write a policy from the ZPL source and configuration.
    pub fn compile(&mut self) -> Result<(), CompilationError> {
        let cctx = CompilationCtx::new(self.verbose, self.werror);
        let pol = self.compile_to_policy(&cctx)?;
        cctx.info("build successful");
        if let Some(pol) = pol {
            let container_bytes = match self.output_format {
                OutputFormat::V1 => {
                    self.contain_policy(pol, &cctx, PolicyContainerV1::default())?
                }
                OutputFormat::V2 => {
                    self.contain_policy(pol, &cctx, PolicyContainerV2::default())?
                }
            };
            self.write_container(&container_bytes, &self.output_file, &cctx)?;
        }
        Ok(())
    }

    pub fn compile_to_policy(
        &mut self,
        cctx: &CompilationCtx,
    ) -> Result<Option<Vec<u8>>, CompilationError> {
        if self.verbose {
            println!(
                "compiling {:?} with config {:?}",
                self.source_zpl, self.source_config
            );
        }
        let cfg = ConfigApi::new_from_toml_file(&self.source_config, &cctx).map_err(|e| {
            CompilationError::ConfigError(format!(
                "failed to load configuration from {:?}: {}",
                self.source_config, e
            ))
        })?;

        let tz = tokenize(&self.source_zpl, &cctx)?;
        if self.verbose {
            println!("parsed {} tokens:", tz.tokens.len());
            for t in &tz.tokens {
                println!("   {:?}", t);
            }
            println!();
        }

        let pr = parse(tz.tokens, &cctx)?;
        let mut policy = pr.policy;
        let policy_digest = sha256_of_file(&self.source_zpl)?;
        policy.digest = Some(policy_digest);

        let fabric = weave(self, &cfg, &policy, &cctx)?;
        if self.verbose {
            println!();
            println!("fabric production:\n{}", fabric);
        }

        cctx.info("parse successful");
        if self.parse_only {
            return Ok(None);
        }

        let policy_bytes = match self.output_format {
            OutputFormat::V1 => {
                let writer = PolicyBinaryV1::new();
                let mut builder = PolicyBuilder::new(self.verbose, writer);
                builder.with_max_visa_lifetime(Duration::from_secs(60 * 60 * 12)); // 12 hours (TODO: Should come from config)
                builder.with_fabric(&fabric, &cctx)?;
                builder.build()?
            }
            OutputFormat::V2 => {
                let writer = PolicyBinaryV2::new(self.v2_memory.as_mut().unwrap());
                let mut builder = PolicyBuilder::new(self.verbose, writer);
                builder.with_max_visa_lifetime(Duration::from_secs(60 * 60 * 12)); // 12 hours (TODO: Should come from config)
                builder.with_fabric(&fabric, &cctx)?;
                builder.build()? // XXX I need the memory here!!
            }
        };
        cctx.info("build successful");
        Ok(Some(policy_bytes))
    }

    /// Write the policy container to the output file, serializing with protocol buffers.
    fn write_container(
        &self,
        container: &[u8],
        file: &Path,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        std::fs::write(file, container).map_err(|e| {
            CompilationError::FileError(format!(
                "failed to write policy container to {:?}: {}",
                file, e
            ))
        })?;
        ctx.info(&format!("wrote {}", &file.display()));
        Ok(())
    }

    /// Create the container struct, move policy into it and optionally sign the policy with the private key.
    fn contain_policy<T>(
        &self,
        pol_buf: Vec<u8>,
        ctx: &CompilationCtx,
        container: T,
    ) -> Result<Vec<u8>, CompilationError>
    where
        T: PolicyContainer,
    {
        let signature = match self.private_key {
            Some(ref key) => {
                let sig = sign_pkcs1v15_sha256(key, &pol_buf)?;
                Some(sig)
            }
            None => {
                ctx.warn(
                    "policy not signed, use `--key <pemfile>` to specify a private key for signing",
                )?;
                None
            }
        };
        container.contain_policy(pol_buf, signature)
    }
}

#[derive(Debug, Default)]
pub enum OutputFormat {
    #[default]
    V1,
    V2,
}

/// The entry point for the compilation process, this builder is used to configure
/// the various settings for the compiler.
#[derive(Default)]
pub struct CompilationBuilder {
    source_zpl: PathBuf,
    source_config: Option<PathBuf>,
    verbose: bool,
    werror: bool,
    private_key: Option<Rsa<Private>>,
    parse_only: bool,
    output_directory: Option<PathBuf>,
    out_filename: Option<String>,
    output_format: OutputFormat,
}

impl CompilationBuilder {
    /// Takes the ZPL source file. By default the configuration file is assumed
    /// to have the same base name but with a `.zplc` extension instead of `.zpl`.
    pub fn new(source: PathBuf) -> Self {
        Self {
            source_zpl: source,
            ..Default::default()
        }
    }

    /// Enable verbose console output from the compilation process.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// If set true, treat warnings as errors and halt compilation when they occur.
    pub fn werror(mut self, werror: bool) -> Self {
        self.werror = werror;
        self
    }

    /// Just builds the fabric in memory, does not try to create the policy protobuf binary.
    pub fn parse_only(mut self, parse_only: bool) -> Self {
        self.parse_only = parse_only;
        self
    }

    /// Set the path to the configuration to use with the compilation.
    /// This is optional. If not set, the configuration file is assumed to have
    /// the same base name as the source file but with a `.zplc` extension.
    pub fn config(mut self, config: &Path) -> Self {
        self.source_config = Some(config.into());
        self
    }

    pub fn sign_with_key(mut self, key: Rsa<Private>) -> Self {
        self.private_key = Some(key);
        self
    }

    pub fn output_directory(mut self, output_directory: &Path) -> Self {
        self.output_directory = Some(output_directory.into());
        self
    }

    pub fn output_filename(mut self, out_filename: &str) -> Self {
        self.out_filename = Some(out_filename.into());
        self
    }

    pub fn output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }

    /// Create the [Compilation] object with the settings configured.
    pub fn build(self) -> Compilation {
        // Default config is same name as source replace .zpl extension with .zplc extension
        let config = match self.source_config {
            Some(config) => config,
            None => {
                let mut config = self.source_zpl.clone();
                config.set_extension("zplc");
                config
            }
        };

        let default_extension = match self.output_format {
            OutputFormat::V1 => "bin",
            OutputFormat::V2 => "bin2",
        };

        let mut output_file = match self.output_directory {
            Some(outdir) => {
                if !outdir.is_dir() {
                    panic!(
                        "output directory {:?} does not exist or is not a directory",
                        outdir
                    );
                }
                let ofile = self.source_zpl.with_extension(default_extension);
                outdir.join(ofile.file_name().unwrap())
            }
            None => self.source_zpl.with_extension(default_extension),
        };

        // If user has selected an alternate output file, substitute that in now.
        if let Some(out_filename) = self.out_filename {
            let base = output_file.parent().unwrap();
            output_file = base.join(out_filename);
        }
        let v2_memory = match self.output_format {
            OutputFormat::V2 => Some(PbV2Memory::new()),
            _ => None,
        };

        Compilation {
            verbose: self.verbose,
            werror: self.werror,
            source_zpl: self.source_zpl,
            source_config: config,
            output_file,
            private_key: self.private_key,
            parse_only: self.parse_only,
            output_format: self.output_format,
            v2_memory,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use polio::polio;
    use prost::Message;
    use std::env;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir {
        path: PathBuf,
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path)
                .expect("failed to remove compilation test temp dir");
        }
    }

    impl TempDir {
        fn new(name_hint: &str) -> Self {
            let mut temp_dir = env::temp_dir();
            temp_dir.push(format!(
                "compilation-test-{}-{}-{}",
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

    const BASIC_CONFIG: &str = r#"
    [nodes.n0]
    key = "none"
    zpr_address = "fd5a:5052:90de::1"
    interfaces = [ "in1" ]
    in1.netaddr = "127.0.0.1:5000"
    provider = [["endpoint.zpr.adapter.cn", "fee"]]

    [visa_service]
    dock_node = "n0"

    [trusted_services.default]
    cert_path = ""

    [protocols.http]
    l4protocol = "iana.TCP"
    port = 80

    [services.Webby]
    protocol = "http"
    "#;

    // Includes a trusted service
    const BAS_CONFIG: &str = r#"
    [nodes.n0]
    key = "none"
    zpr_address = "fd5a:5052:90de::1"
    interfaces = [ "in1" ]
    in1.netaddr = "127.0.0.1:5000"
    provider = [["endpoint.zpr.adapter.cn", "fee"]]

    [visa_service]
    dock_node = "n0"

    [trusted_services.default]
    cert_path = ""

    [trusted_services.bas]
    api = "validation/2"
    client = "AuthService"
    cert_path = ""
    returns_attributes = [ "user.color", "service.content", "user.bas_id" ]
    identity_attributes = [ "user.bas_id" ]
    provider = [[ "endpoint.zpr.adapter.cn", "bas.zpr.org" ]]


    [protocols.http]
    l4protocol = "iana.TCP"
    port = 80

    [services.Webby]
    protocol = "http"

    [services.bas-vs]
    protocol = "zpr-validation2"

    [services.AuthService]
    protocol = "zpr-oauthrsa"
    "#;

    #[test]
    fn simple_compile() {
        let zpl = r#"
        define Webby as service with endpoint.zpr.adapter.cn
        allow zpr.adapter.cn: endpoints to access Webby
        "#;

        let tempdir = TempDir::new("simple_compile");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(
            result.is_ok(),
            "compilation failed: {}",
            result.unwrap_err()
        );
    }

    // In this case with is required since there is no provider in config.
    #[test]
    fn define_requires_with() {
        let zpl = r#"
        define Webby as service
        allow zpr.adapter.cn: endpoints to access Webby
        "#;

        let tempdir = TempDir::new("define_requires_with");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("service with no attributes"),
            "unexpected error message: {}",
            err_msg
        );
    }

    // In this case with is not required since we have attributes in conifg.
    #[test]
    fn define_ok_without_with() {
        let zplc = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["endpoint.zpr.adapter.cn", "fee"]]

        [visa_service]
        dock_node = "n0"

        [trusted_services.default]
        cert_path = ""

        [protocols.http]
        l4protocol = "iana.TCP"
        port = 80

        [services.Webby]
        protocol = "http"
        provider = [["endpoint.zpr.adapter.cn", ""]]
        "#;

        let zpl = r#"
        define Webby as service
        allow zpr.adapter.cn: endpoints to access Webby
        "#;

        let tempdir = TempDir::new("define_ok_without_with");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, zplc).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(
            result.is_ok(),
            "compilation failed: {}",
            result.unwrap_err()
        );
    }

    #[test]
    fn cannot_use_cn_as_tag() {
        let zpl = r#"
        define Webby as service with endpoint.zpr.adapter.cn
        allow zpr.adapter.cn endpoints to access Webby
        "#;

        let tempdir = TempDir::new("cannot_use_cn_as_tag");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cn attribute used as a tag"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    fn test_svc_attrs_must_be_defined() {
        let zpl = r#"
        define Webby as service with unknown_attr
        allow cn: endpoints to access services
        "#;

        let tempdir = TempDir::new("test_svc_attrs_must_be_defined");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown_attr not found"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    fn test_allow_attrs_must_be_defined() {
        let zpl = r#"
        define Webby as service with endpoint.zpr.adapter.cn
        allow unknown_attr: endpoints to access services
        "#;

        let tempdir = TempDir::new("test_allow_attrs_must_be_defined");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("endpoint.unknown_attr: not found"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    fn test_service_attributes() {
        let zpl = r#"
        define Webby as a service with user.bas_id:100.
        allow color:green users to access content:green services.
        allow color:brown users to access content:brown services.
        allow color:red users to access Webby.
        "#;

        let tempdir = TempDir::new("test_service_attributes");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BAS_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let ctx = CompilationCtx::new(true, false);
        let result = compilation.compile_to_policy(&ctx);
        match result {
            Ok(pol) => {
                let pol_bin = pol.unwrap();
                let pol: polio::Policy = polio::Policy::decode(pol_bin.as_slice())
                    .expect("failed to decode binary policy file");

                let mut pcount = 0;

                // We are looking for three things in the policy encoded in `matched` as follows:
                // 00000001 = found the color:red condition
                // 00000010 = found the color:brown condition
                // 00000100 = found the color:green condition
                let mut matched: u8 = 0;

                for plcy in &pol.policies {
                    if plcy.service_id != "Webby" {
                        continue;
                    }
                    pcount += 1;
                    if plcy.svc_conditions.is_empty() {
                        // Then there should be a cli condition on color:red
                        if plcy.cli_conditions.len() != 1 {
                            assert!(
                                false,
                                "expected 1 cli condition for color:red, got {}",
                                plcy.cli_conditions.len()
                            );
                        }
                        let cond = &plcy.cli_conditions[0];
                        let expr = &cond.attr_exprs[0];
                        let kval = pol.attr_key_index[expr.key as usize].clone();
                        let vval = pol.attr_val_index[expr.val as usize].clone();
                        assert!(
                            kval == "user.color" && vval == "red",
                            "expected user.color:purple, got {}:{}",
                            kval,
                            vval
                        );
                        matched |= 0b00000001;
                    } else {
                        // The other two policies should each have one cli_conditiona and one svc_condition.
                        // The expected values are:
                        //    - user.color EQ green WITH service.content EQ green
                        //    - user.color EQ brown WITH service.content EQ brown
                        let svc_cond = &plcy.svc_conditions[0];
                        let svc_expr = &svc_cond.attr_exprs[0];
                        let svc_kval = pol.attr_key_index[svc_expr.key as usize].clone();
                        let svc_vval = pol.attr_val_index[svc_expr.val as usize].clone();
                        assert!(
                            svc_kval == "service.content",
                            "expected service.content, got {}",
                            svc_kval
                        );
                        if svc_vval == "brown" {
                            // Then there should be a cli condition on color:brown
                            let cond = &plcy.cli_conditions[0];
                            let expr = &cond.attr_exprs[0];
                            let kval = pol.attr_key_index[expr.key as usize].clone();
                            let vval = pol.attr_val_index[expr.val as usize].clone();
                            assert!(
                                kval == "user.color" && vval == "brown",
                                "expected user.color:brown, got {}:{}",
                                kval,
                                vval
                            );
                            matched |= 0b00000010;
                        } else {
                            // Then there should be a cli condition on color:green
                            let cond = &plcy.cli_conditions[0];
                            let expr = &cond.attr_exprs[0];
                            let kval = pol.attr_key_index[expr.key as usize].clone();
                            let vval = pol.attr_val_index[expr.val as usize].clone();
                            assert!(
                                kval == "user.color" && vval == "green",
                                "expected user.color:green, got {}:{}",
                                kval,
                                vval
                            );
                            matched |= 0b00000100;
                        }
                    }
                }
                assert!(pcount == 3, "expected 3 policies for Webby, got {}", pcount);
                assert!(
                    matched == 0b00000111,
                    "did not match all expected policies, got {:03b}",
                    matched
                );
            }
            Err(err) => {
                assert!(false, "compilation failed: {}", err);
            }
        }
    }
}
