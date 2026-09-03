# Security policy

## Scope

`bininspect` reads binary bytes and reports claims found in them. It does not execute the inspected binary, load its libraries, resolve network sources, or reconstruct dependencies that are not represented in embedded metadata. An unresolved report is a non-pass result.

The input limit is 64 MiB and the decompressed provenance JSON limit is 8 MiB. ELF section counts are bounded. Absolute input paths are redacted in reports, and source claims are emitted as source categories rather than local paths.

## Supported versions

The latest `0.1.x` release is supported.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting or open a private GitHub Security Advisory for this repository. Do not include a sensitive binary in a public issue.

Reports are most useful when they include the binary format, the smallest reproducing input, the observed report and exit code, and the `bininspect` version. Remove secrets and private paths before sending an input.

## Security design

The inspector uses bounded reads, checked integer arithmetic, and the maintained `auditable-info` parser for compressed provenance data. Malformed and truncated inputs remain unresolved. A missing claim is reported as missing and never as proof that a dependency or compiler is absent.
