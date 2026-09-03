# Release checklist

Release `bininspect` only after all of the following are observed in the current checkout:

- `cargo fmt --all -- --check`
- `cargo check --all-targets --locked`
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `cargo test --all-targets --locked`
- `RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked`
- `cargo package --locked`
- `cargo audit`
- `git diff --check`
- a bounded nightly fuzz run with a hard timeout
- a clean `cargo install` from the packaged crate in a fresh temporary directory
- fixture and CLI smoke tests for exact metadata, stripped input, malformed input, unsupported input, and oversized input
- successful GitHub Actions CI, Security, CodeQL, and tag package checks
- repository branch protection and secret scanning settings verified
- a GitHub release and crates.io publication whose hashes and URLs are recorded in private QA evidence

The unresolved state must remain nonzero in automation. Do not describe symbol scanning as dependency reconstruction, or claim PE/COFF, Mach-O, or WebAssembly compiler extraction until separately bounded implementations and tests exist.
