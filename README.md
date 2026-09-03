# bininspect

`bininspect` inspects a compiled binary and reports the Rust dependency provenance and compiler claims that are embedded in it. The Linux-first MVP parses ELF section metadata and consumes the standard `cargo-auditable` `.dep-v0` format.

It never treats a missing provenance claim as proof that a dependency is absent. Every claim has a state and confidence value: `exact`, `inferred`, `missing`, or `unresolved`.

## Usage

```text
bininspect inspect ./binary
bininspect dependencies ./binary
bininspect export ./binary --format json
```

`inspect` and `dependencies` use readable text by default. `export` uses JSON by default. Any command accepts `--format text` or `--format json`.

Exit codes are stable:

- `0`: the supported input was parsed without a reported discrepancy;
- `2`: the input was parsed and a discrepancy was found;
- `3`: the input is unsupported, malformed, truncated, over a configured limit, or could not be inspected.

The JSON report includes the detected format, compiler claim, provenance state, package names and versions, source categories, dependency indexes, discrepancies, warnings, and the active limits. Absolute input paths are reduced to `<absolute>/<filename>`.

## Scope

The MVP supports ELF parsing on Linux and recognizes PE/COFF, Mach-O, and WebAssembly inputs for the standard auditable extractor. Compiler extraction is currently implemented only for the ELF `.comment` section. Unknown formats and Unix `ar` archives are unresolved.

The package tree is provenance data from the binary, not a perfect reconstruction of every dependency used at runtime. Build metadata can include build-time packages, multiple versions of a package, or source categories without a complete source URL.

## Development

```bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked
cargo package --locked
```

The fuzz target is in `fuzz/` and is run with a hard timeout by the release checklist. See [`docs/research.md`](docs/research.md), [`docs/release.md`](docs/release.md), and [`SECURITY.md`](SECURITY.md) for the evidence boundary and release policy.
