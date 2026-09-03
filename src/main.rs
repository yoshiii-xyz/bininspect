use std::{path::PathBuf, process::ExitCode};

use bininspect::{Report, inspect_path, render_json, render_text};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "bininspect",
    version,
    about = "Inspect Rust binary dependency provenance"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Inspect {
        binary: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    Dependencies {
        binary: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    Export {
        binary: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (binary, format) = match cli.command {
        Command::Inspect { binary, format } => (binary, format),
        Command::Dependencies { binary, format } => (binary, format),
        Command::Export { binary, format } => (binary, format),
    };

    let report = match inspect_path(&binary) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("bininspect: {error}");
            return ExitCode::from(3);
        }
    };
    if let Err(error) = print_report(&report, format) {
        eprintln!("bininspect: could not render report: {error}");
        return ExitCode::from(3);
    }
    ExitCode::from(report.exit_code() as u8)
}

fn print_report(report: &Report, format: OutputFormat) -> serde_json::Result<()> {
    match format {
        OutputFormat::Text => {
            print!("{}", render_text(report));
            Ok(())
        }
        OutputFormat::Json => {
            println!("{}", render_json(report)?);
            Ok(())
        }
    }
}
