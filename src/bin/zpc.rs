
use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use zplc::compilation::Compilation;
use zplc::crypto::load_rsa_private_key;

/// zpc: the ZPL Compiler
///
/// Compile a ZPL policy (plus its configuration) into a binary format for the
/// visa service.
#[derive(Debug, Parser)]
#[command(name = "zpc")]
#[command(version = "0.2.0", verbatim_doc_comment)] // hmm can get grab this from Cargo?
struct Cli {
    /// Path to the ZPL file.
    #[arg(value_name = "ZPL_FILE")]
    zpl: PathBuf,

    /// Path to a priate RSA key to sign the compiled policy with.
    #[arg(short, long, value_name = "FILE")]
    key: Option<PathBuf>,

    /// Load configuration from ZPLC_FILE instead of the default.
    #[arg(short = 'c', long = "config", value_name = "ZPLC_FILE")]
    zplc: Option<PathBuf>,

    /// Write output binary to existing directory DIR instead of default.
    #[arg(short = 'd', long = "outdir", value_name = "DIR")]
    outdir: Option<PathBuf>,

    /// Write the binary policy to filed named NAME instead of the default (input file with extension switched to .bin)
    #[arg(short = 'o', long, value_name = "NAME")]
    outfname: Option<String>,

    /// Sets extra verbosity.
    #[arg(short, long)]
    verbose: bool,

    /// Only perform parsing step. Does not produce a binary policy.
    #[arg(short, long)]
    parse_only: bool,

    /// Treat warnings like errors and halt compilation when they occur.
    #[arg(long = "Werror")]
    werror: bool,
}

fn main() {
    let mut exit_code = 0;
    let cli = Cli::parse();
    let mut cb = Compilation::builder(cli.zpl)
        .verbose(cli.verbose)
        .werror(cli.werror);
    if cli.parse_only {
        cb = cb.parse_only(true);
    }
    if let Some(cfg) = cli.zplc {
        cb = cb.config(&cfg);
    }
    if let Some(outdir) = cli.outdir {
        cb = cb.output_directory(&outdir);
    }
    if let Some(outfname) = cli.outfname {
        cb = cb.output_filename(&outfname);
    }
    if let Some(key) = cli.key {
        let key = match load_rsa_private_key(&key) {
            Ok(k) => k,
            Err(e) => {
                println!(
                    "{}{} failed to load private key: {}",
                    "error".red().bold(),
                    ":".bold(),
                    e
                );
                std::process::exit(1);
            }
        };
        cb = cb.sign_with_key(key);
    }
    let comp = cb.build();
    match comp.compile() {
        Ok(_) => (),
        Err(e) => {
            println!("{}{} {}", "error".red().bold(), ":".bold(), e);
            exit_code = 1;
        }
    }
    std::process::exit(exit_code);
}
