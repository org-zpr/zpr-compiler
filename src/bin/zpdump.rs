use bytes::Bytes;
use clap::Parser;
use std::path::PathBuf;
use zplc::dump;

/// ZPL Policy Dumper
///
/// Prints contents of a binary policy file to stdout.
#[derive(Debug, Parser)]
#[command(name = "zpdump")]
#[command(version, verbatim_doc_comment)]
struct Cli {
    /// Path to the ZPL file.
    #[arg(value_name = "ZPL_FILE")]
    zpl: PathBuf,
}

fn main() {
    let exit_code = 0;
    let cli = Cli::parse();

    let fname = cli.zpl.display().to_string();
    let encoded = std::fs::read(cli.zpl).expect("failed to read binary policy file");
    let encoded_buf = Bytes::from(encoded);
    if fname.ends_with(".bin2") {
        dump::dump_v2(&fname, encoded_buf);
    } else {
        dump::dump_v1(&fname, encoded_buf);
    }
    std::process::exit(exit_code);
}
