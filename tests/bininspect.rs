use std::{fs, path::PathBuf, process::Command};

use bininspect::{
    ClaimState, MAX_BINARY_BYTES, inspect_bytes, inspect_path, provenance_span, render_json,
};

fn fixture_bytes() -> Vec<u8> {
    fs::read(env!("CARGO_BIN_EXE_bininspect")).expect("built bininspect fixture")
}

#[test]
fn inspects_fixture_with_exact_metadata() {
    let report = inspect_bytes("/home/private/build/bininspect", &fixture_bytes());

    assert_eq!(report.format.name, "ELF");
    assert!(report.format.supported);
    assert!(report.parsed);
    assert_eq!(report.compiler.state, ClaimState::Exact);
    assert_eq!(report.provenance.state, ClaimState::Exact);
    assert!(
        report
            .provenance
            .packages
            .iter()
            .any(|package| package.name == "bininspect")
    );
    assert_eq!(report.input, "<absolute>/bininspect");
    assert!(
        !render_json(&report)
            .expect("json")
            .contains("/home/private")
    );
}

#[test]
fn inspects_stripped_binary_without_panicking() {
    let path = unique_temp_path("stripped");
    fs::write(&path, fixture_bytes()).expect("write strip fixture");
    let status = Command::new("strip")
        .args(["--strip-all", path.to_str().expect("utf8 temp path")])
        .status()
        .expect("strip is installed on the Linux MVP runner");
    assert!(status.success());

    let report = inspect_path(&path).expect("inspect stripped fixture");
    assert_eq!(report.format.name, "ELF");
    assert!(report.format.supported);
    assert!(report.parsed);
}

#[test]
fn rejects_unsupported_format() {
    let report = inspect_bytes("archive", b"!<arch>\n");

    assert_eq!(report.format.name, "ar archive");
    assert!(!report.format.supported);
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn handles_truncated_binary() {
    let report = inspect_bytes("truncated", b"\x7fELF");

    assert_eq!(report.format.name, "ELF");
    assert!(!report.parsed);
    assert_eq!(report.provenance.state, ClaimState::Unresolved);
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn handles_corrupted_embedded_metadata() {
    let mut bytes = fixture_bytes();
    let (offset, size) = provenance_span(&bytes).expect("fixture has .dep-v0");
    assert!(size > 1);
    bytes[offset] ^= 0xff;

    let report = inspect_bytes("corrupted", &bytes);
    assert_eq!(report.provenance.state, ClaimState::Unresolved);
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn enforces_large_binary_bound() {
    let bytes = vec![0; MAX_BINARY_BYTES + 1];
    let report = inspect_bytes("large", &bytes);

    assert_eq!(report.status, "unresolved");
    assert_eq!(report.exit_code(), 3);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("above"))
    );
}

#[test]
fn renders_stable_machine_readable_output() {
    let report = inspect_bytes("stable", &fixture_bytes());
    let first = render_json(&report).expect("first json");
    let second = render_json(&report).expect("second json");

    assert_eq!(first, second);
    let parsed: serde_json::Value = serde_json::from_str(&first).expect("valid json");
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["tool"], "bininspect");
}

#[test]
fn cli_commands_emit_reports() {
    let fixture = env!("CARGO_BIN_EXE_bininspect");
    let dependencies = Command::new(fixture)
        .args(["dependencies", fixture])
        .output()
        .expect("dependencies command");
    assert!(dependencies.status.code().is_some_and(|code| code <= 3));
    assert!(String::from_utf8_lossy(&dependencies.stdout).contains("provenance:"));

    let exported = Command::new(fixture)
        .args(["export", fixture, "--format", "json"])
        .output()
        .expect("export command");
    assert!(exported.status.code().is_some_and(|code| code <= 3));
    let value: serde_json::Value =
        serde_json::from_slice(&exported.stdout).expect("exported json report");
    assert_eq!(value["tool"], "bininspect");
}

fn unique_temp_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("bininspect-{label}-{}", std::process::id()))
}
