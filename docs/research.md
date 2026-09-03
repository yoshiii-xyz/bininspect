# Research notes

## Boundary

The MVP is a Linux-first inspector for compiled Rust binaries. It must report only claims that can be traced to binary structure or a recognized embedded provenance format. It must not claim perfect dependency reconstruction.

## Evidence used

- The [ELF format reference](https://man7.org/linux/man-pages/man5/elf.5.html) defines the ELF header, program and section headers, section offsets and sizes, `.comment`, and note sections. The [readelf manual](https://man7.org/linux/man-pages/man1/readelf.1.html) describes the standard inspection surface.
- The [GNU binutils documentation](https://sourceware.org/binutils/docs/binutils.html) and [ELF ABI specification](https://refspecs.linuxfoundation.org/elf/elf.pdf) support treating section tables as bounded, untrusted binary input.
- The [Rust compiler codegen documentation](https://doc.rust-lang.org/rustc/codegen-options/) documents metadata and stripping options. Compiler metadata options affect symbol mangling and are not a dependency inventory, so the implementation does not infer a dependency list from symbol names.
- The [Cargo metadata documentation](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html) describes the source graph that the auditable ecosystem consumes.
- The [cargo-auditable README](https://github.com/rust-secure-code/cargo-auditable/blob/master/README.md) documents the `.dep-v0` zlib-compressed dependency tree and compiler information in modern Rust binaries. Its [parsing guide](https://github.com/rust-secure-code/cargo-auditable/blob/master/PARSING.md) recommends a decompressed JSON bound and validation of the package graph.
- The [auditable-info API](https://docs.rs/auditable-info/latest/auditable_info/fn.audit_info_from_slice.html) provides bounded extraction from ELF, PE, Mach-O, and WebAssembly binaries. Its [`Limits`](https://docs.rs/auditable-info/latest/auditable_info/struct.Limits.html) API makes the input and decompressed JSON bounds explicit.
- The [auditable-serde API](https://docs.rs/auditable-serde/latest/auditable_serde/) exposes package names, semantic versions, source categories, dependency indexes, and the format revision. Deserialization validates the graph against multiple roots and cycles.

## Design decisions

1. Use `auditable-info` for `.dep-v0` extraction instead of inventing a marker or manually reimplementing zlib parsing.
2. Parse ELF headers and section tables with checked, allocation-bounded code so `.comment` can provide an exact compiler claim and malformed input can be classified safely.
3. Use `exact` only for claims directly read from `.dep-v0` or a valid ELF `.comment` record. Use `missing` when a recognized format has no claim, and `unresolved` when the format or data cannot be safely parsed. The `inferred` state remains available for future evidence that is weaker than a direct claim.
4. Emit source categories and redact absolute paths. The report exposes the provenance claim without turning a local build path into output data.
5. Treat duplicate records, multiple versions for one package name, source-category conflicts, invalid dependency indexes, and compiler-version conflicts as discrepancies. Multiple package versions can be valid Cargo output, so the report keeps the full package list and makes the discrepancy visible rather than collapsing records.

## Known limits

- Only ELF structure and `.comment` compiler records are parsed directly in this MVP.
- PE/COFF, Mach-O, and WebAssembly are recognized for the standard auditable extractor but do not receive an equivalent compiler-section claim.
- A missing `.dep-v0` claim does not prove that no dependencies exist.
- Symbols, strings, linker notes, and binary size cannot establish a complete dependency inventory.
- The inspector does not verify that the embedded claim matches a source checkout or a particular build invocation.
