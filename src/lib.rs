use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read},
    path::Path,
};

use auditable_serde::{DependencyKind, Source, VersionInfo};
use serde::Serialize;

#[allow(dead_code)]
static COMPRESSED_DEPENDENCY_LIST: &[u8] = auditable::inject_dependency_list!();

pub const MAX_BINARY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PROVENANCE_JSON_BYTES: usize = 8 * 1024 * 1024;

const MAX_ELF_SECTIONS: u64 = 1_000_000;
const SHT_NOBITS: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    Exact,
    Inferred,
    Missing,
    Unresolved,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClaimReport {
    pub state: ClaimState,
    pub confidence: ClaimState,
    pub value: Option<String>,
    pub source: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FormatReport {
    pub name: String,
    pub supported: bool,
    pub parse_state: String,
    pub class: Option<String>,
    pub endianness: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompilerReport {
    pub state: ClaimState,
    pub confidence: ClaimState,
    pub value: Option<String>,
    pub versions: Vec<String>,
    pub source: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackageReport {
    pub name: String,
    pub version: String,
    pub source_claim: String,
    pub kind: String,
    pub root: bool,
    pub dependencies: Vec<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProvenanceReport {
    pub state: ClaimState,
    pub confidence: ClaimState,
    pub format_revision: Option<u32>,
    pub source: Option<String>,
    pub packages: Vec<PackageReport>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Discrepancy {
    pub kind: String,
    pub package: Option<String>,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LimitsReport {
    pub max_binary_bytes: usize,
    pub max_provenance_json_bytes: usize,
    pub max_elf_sections: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub tool: String,
    pub input: String,
    pub status: String,
    pub parsed: bool,
    pub format: FormatReport,
    pub compiler: CompilerReport,
    pub provenance: ProvenanceReport,
    pub discrepancies: Vec<Discrepancy>,
    pub warnings: Vec<String>,
    pub limits: LimitsReport,
}

impl Report {
    pub fn exit_code(&self) -> i32 {
        match self.status.as_str() {
            "ok" => 0,
            "discrepancy" => 2,
            _ => 3,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Endianness {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug)]
enum ElfClass {
    Class32,
    Class64,
}

#[derive(Clone, Debug)]
struct ElfSection {
    name: String,
    section_type: u32,
    offset: usize,
    size: usize,
}

#[derive(Clone, Debug)]
struct ElfFile {
    class: ElfClass,
    endianness: Endianness,
    sections: Vec<ElfSection>,
}

#[derive(Clone, Debug)]
struct DetectedFormat {
    report: FormatReport,
    elf: Option<ElfFile>,
}

pub fn inspect_path(path: &Path) -> io::Result<Report> {
    let input = redact_path(&path.to_string_lossy());
    let input_size = fs::metadata(path)?.len();
    if input_size > MAX_BINARY_BYTES as u64 {
        return Ok(input_limit_report(input, input_size));
    }

    let file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity((input_size as usize).min(MAX_BINARY_BYTES));
    file.take(MAX_BINARY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BINARY_BYTES {
        return Ok(input_limit_report(input, bytes.len() as u64));
    }
    Ok(inspect_bytes(&input, &bytes))
}

pub fn inspect_bytes(input: &str, bytes: &[u8]) -> Report {
    let input = redact_path(input);
    if bytes.len() > MAX_BINARY_BYTES {
        return input_limit_report(input, bytes.len() as u64);
    }

    let detected = detect_format(bytes);
    let mut report = base_report(input, detected.report.clone());
    report.parsed = detected.report.parse_state != "unrecognized"
        && detected.report.parse_state != "unresolved";

    if let Some(elf) = detected.elf.as_ref() {
        let versions = extract_rustc_versions(bytes, elf);
        if versions.is_empty() {
            report.compiler = missing_compiler_report();
            report
                .warnings
                .push("compiler claim is missing from ELF .comment".to_owned());
        } else {
            report.compiler = compiler_report(&versions);
        }
        if versions.len() > 1 {
            report.discrepancies.push(Discrepancy {
                kind: "compiler-version-mismatch".to_owned(),
                package: None,
                detail: format!(
                    ".comment contains multiple rustc versions: {}",
                    versions.join(", ")
                ),
            });
        }
    } else if detected.report.supported && report.parsed {
        report
            .warnings
            .push("compiler claim is missing outside the Linux ELF .comment extractor".to_owned());
        report.compiler = missing_compiler_report();
    } else if !detected.report.supported {
        report.compiler = unresolved_compiler_report();
        report
            .warnings
            .push("compiler claim was not inspected because the format is unsupported".to_owned());
    } else {
        report.compiler = unresolved_compiler_report();
    }

    if detected.report.supported && report.parsed {
        match auditable_info::audit_info_from_slice(bytes, MAX_PROVENANCE_JSON_BYTES) {
            Ok(info) => {
                let (provenance, discrepancies) = provenance_report(&info);
                report.provenance = provenance;
                report.discrepancies.extend(discrepancies);
            }
            Err(auditable_info::Error::NoAuditData) => {
                report.provenance = missing_provenance_report();
                report.warnings.push(
                    "embedded provenance claim is missing; this does not prove a dependency is absent"
                        .to_owned(),
                );
            }
            Err(error) => {
                report.provenance = unresolved_provenance_report();
                report.warnings.push(format!(
                    "embedded provenance could not be resolved: {error}"
                ));
            }
        }
    } else if !detected.report.supported {
        report.provenance = unresolved_provenance_report();
        report.warnings.push(
            "embedded provenance was not inspected because the format is unsupported".to_owned(),
        );
    } else {
        report.provenance = unresolved_provenance_report();
        report.warnings.push(
            "embedded provenance was not inspected because binary parsing is unresolved".to_owned(),
        );
    }

    finalize(&mut report);
    report
}

pub fn render_json(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

pub fn render_text(report: &Report) -> String {
    let mut output = String::new();
    output.push_str("bininspect schema=1\n");
    output.push_str(&format!("input: {}\n", report.input));
    output.push_str(&format!("status: {}\n", report.status));
    output.push_str(&format!("parsed: {}\n", report.parsed));
    output.push_str(&format!(
        "format: {} supported={} parse_state={} class={} endianness={}\n",
        report.format.name,
        report.format.supported,
        report.format.parse_state,
        optional_value(report.format.class.as_deref()),
        optional_value(report.format.endianness.as_deref())
    ));
    output.push_str(&format!(
        "compiler: state={} confidence={} value={} versions={} source={}\n",
        state_value(report.compiler.state),
        state_value(report.compiler.confidence),
        optional_value(report.compiler.value.as_deref()),
        if report.compiler.versions.is_empty() {
            "none".to_owned()
        } else {
            report.compiler.versions.join(",")
        },
        optional_value(report.compiler.source.as_deref())
    ));
    output.push_str(&format!(
        "provenance: state={} confidence={} format_revision={} source={}\n",
        state_value(report.provenance.state),
        state_value(report.provenance.confidence),
        report
            .provenance
            .format_revision
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        optional_value(report.provenance.source.as_deref())
    ));

    if report.provenance.packages.is_empty() {
        output.push_str("packages: none\n");
    } else {
        output.push_str(&format!("packages: {}\n", report.provenance.packages.len()));
        for package in &report.provenance.packages {
            let dependencies = package
                .dependencies
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",");
            output.push_str(&format!(
                "- {} {} source={} kind={} root={} dependencies={}\n",
                package.name,
                package.version,
                package.source_claim,
                package.kind,
                package.root,
                if dependencies.is_empty() {
                    "none"
                } else {
                    &dependencies
                }
            ));
        }
    }

    if report.discrepancies.is_empty() {
        output.push_str("discrepancies: none\n");
    } else {
        output.push_str("discrepancies:\n");
        for discrepancy in &report.discrepancies {
            output.push_str(&format!(
                "- {} package={} detail={}\n",
                discrepancy.kind,
                optional_value(discrepancy.package.as_deref()),
                discrepancy.detail
            ));
        }
    }

    if report.warnings.is_empty() {
        output.push_str("warnings: none\n");
    } else {
        output.push_str("warnings:\n");
        for warning in &report.warnings {
            output.push_str(&format!("- {warning}\n"));
        }
    }
    output.push_str(&format!(
        "limits: max_binary_bytes={} max_provenance_json_bytes={} max_elf_sections={}\n",
        report.limits.max_binary_bytes,
        report.limits.max_provenance_json_bytes,
        report.limits.max_elf_sections
    ));
    output
}

pub fn redact_path(input: &str) -> String {
    let input = clean_display(input);
    if input.starts_with('/') {
        match Path::new(&input).file_name() {
            Some(name) if !name.is_empty() => {
                format!("<absolute>/{}", clean_display(&name.to_string_lossy()))
            }
            _ => "<absolute>".to_owned(),
        }
    } else if is_windows_absolute(&input) {
        match input.rsplit(['\\', '/']).next() {
            Some(name) if !name.is_empty() => format!("<absolute>/{}", clean_display(name)),
            _ => "<absolute>".to_owned(),
        }
    } else {
        input
    }
}

pub fn provenance_span(bytes: &[u8]) -> Option<(usize, usize)> {
    let elf = parse_elf(bytes).ok()?;
    let section = elf
        .sections
        .iter()
        .find(|section| section.name == ".dep-v0")?;
    section.offset.checked_add(section.size)?;
    Some((section.offset, section.size))
}

fn base_report(input: String, format: FormatReport) -> Report {
    Report {
        schema_version: 1,
        tool: "bininspect".to_owned(),
        input,
        status: "unresolved".to_owned(),
        parsed: false,
        format,
        compiler: unresolved_compiler_report(),
        provenance: unresolved_provenance_report(),
        discrepancies: Vec::new(),
        warnings: Vec::new(),
        limits: LimitsReport {
            max_binary_bytes: MAX_BINARY_BYTES,
            max_provenance_json_bytes: MAX_PROVENANCE_JSON_BYTES,
            max_elf_sections: MAX_ELF_SECTIONS,
        },
    }
}

fn input_limit_report(input: String, size: u64) -> Report {
    let mut report = base_report(
        input,
        FormatReport {
            name: "unknown".to_owned(),
            supported: false,
            parse_state: "unresolved".to_owned(),
            class: None,
            endianness: None,
        },
    );
    report.warnings.push(format!(
        "input is {size} bytes, above the {} byte limit",
        MAX_BINARY_BYTES
    ));
    report
}

fn finalize(report: &mut Report) {
    if report.format.supported
        && report.parsed
        && report.provenance.state != ClaimState::Unresolved
        && report.compiler.state != ClaimState::Unresolved
    {
        report.status = if report.discrepancies.is_empty() {
            "ok".to_owned()
        } else {
            "discrepancy".to_owned()
        };
    } else {
        report.status = "unresolved".to_owned();
    }
}

fn detect_format(bytes: &[u8]) -> DetectedFormat {
    if bytes.starts_with(b"\x7fELF") {
        return match parse_elf(bytes) {
            Ok(elf) => DetectedFormat {
                report: FormatReport {
                    name: "ELF".to_owned(),
                    supported: true,
                    parse_state: "parsed".to_owned(),
                    class: Some(match elf.class {
                        ElfClass::Class32 => "ELF32".to_owned(),
                        ElfClass::Class64 => "ELF64".to_owned(),
                    }),
                    endianness: Some(match elf.endianness {
                        Endianness::Little => "little".to_owned(),
                        Endianness::Big => "big".to_owned(),
                    }),
                },
                elf: Some(elf),
            },
            Err(_) => DetectedFormat {
                report: FormatReport {
                    name: "ELF".to_owned(),
                    supported: true,
                    parse_state: "unresolved".to_owned(),
                    class: None,
                    endianness: None,
                },
                elf: None,
            },
        };
    }

    if bytes.starts_with(b"MZ") {
        let parsed = bytes.len() >= 64
            && read_u32_le(bytes, 0x3c)
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| bytes.get(offset..offset.saturating_add(4)))
                == Some(b"PE\0\0");
        return recognized_format("PE/COFF", parsed, true);
    }

    if is_macho_magic(bytes) {
        let parsed = if bytes.starts_with(b"\xca\xfe\xba\xbe")
            || bytes.starts_with(b"\xbe\xba\xfe\xca")
            || bytes.starts_with(b"\xca\xfe\xba\xbf")
            || bytes.starts_with(b"\xbf\xba\xfe\xca")
        {
            bytes.len() >= 8
        } else {
            bytes.len() >= 4
        };
        return recognized_format("Mach-O", parsed, true);
    }

    if bytes.starts_with(b"\0asm") {
        let parsed = bytes.len() >= 8 && bytes[4..8] == [1, 0, 0, 0];
        return recognized_format("WebAssembly", parsed, true);
    }

    if bytes.starts_with(b"!<arch>\n") {
        return recognized_format("ar archive", true, false);
    }

    DetectedFormat {
        report: FormatReport {
            name: "unknown".to_owned(),
            supported: false,
            parse_state: "unrecognized".to_owned(),
            class: None,
            endianness: None,
        },
        elf: None,
    }
}

fn recognized_format(name: &str, parsed: bool, supported: bool) -> DetectedFormat {
    DetectedFormat {
        report: FormatReport {
            name: name.to_owned(),
            supported,
            parse_state: if parsed {
                "recognized".to_owned()
            } else {
                "unresolved".to_owned()
            },
            class: None,
            endianness: None,
        },
        elf: None,
    }
}

fn is_macho_magic(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(b"\xfe\xed\xfa\xce")
            | Some(b"\xce\xfa\xed\xfe")
            | Some(b"\xfe\xed\xfa\xcf")
            | Some(b"\xcf\xfa\xed\xfe")
            | Some(b"\xca\xfe\xba\xbe")
            | Some(b"\xbe\xba\xfe\xca")
            | Some(b"\xca\xfe\xba\xbf")
            | Some(b"\xbf\xba\xfe\xca")
    )
}

fn parse_elf(bytes: &[u8]) -> Result<ElfFile, String> {
    if bytes.len() < 16 {
        return Err("truncated ELF identification".to_owned());
    }
    let class = match bytes[4] {
        1 => ElfClass::Class32,
        2 => ElfClass::Class64,
        _ => return Err("unsupported ELF class".to_owned()),
    };
    let endianness = match bytes[5] {
        1 => Endianness::Little,
        2 => Endianness::Big,
        _ => return Err("unsupported ELF byte order".to_owned()),
    };
    if bytes[6] != 1 {
        return Err("unsupported ELF identification version".to_owned());
    }

    let (header_size, section_offset, section_entry_size, section_count, section_name_index) =
        match class {
            ElfClass::Class32 => {
                if bytes.len() < 52 {
                    return Err("truncated ELF32 header".to_owned());
                }
                (
                    52usize,
                    read_u32(bytes, 32, endianness)? as u64,
                    read_u16(bytes, 46, endianness)? as u64,
                    read_u16(bytes, 48, endianness)? as u64,
                    read_u16(bytes, 50, endianness)? as u64,
                )
            }
            ElfClass::Class64 => {
                if bytes.len() < 64 {
                    return Err("truncated ELF64 header".to_owned());
                }
                (
                    64usize,
                    read_u64(bytes, 40, endianness)?,
                    read_u16(bytes, 58, endianness)? as u64,
                    read_u16(bytes, 60, endianness)? as u64,
                    read_u16(bytes, 62, endianness)? as u64,
                )
            }
        };
    let _ = header_size;

    if section_count == 0 {
        if section_offset != 0 || section_name_index != 0 {
            return Err("extended or malformed ELF section numbering".to_owned());
        }
        return Ok(ElfFile {
            class,
            endianness,
            sections: Vec::new(),
        });
    }
    if section_offset == 0 {
        return Err("ELF section table offset is missing".to_owned());
    }
    if section_count > MAX_ELF_SECTIONS {
        return Err("ELF section count exceeds the configured limit".to_owned());
    }

    let minimum_entry_size = match class {
        ElfClass::Class32 => 40u64,
        ElfClass::Class64 => 64u64,
    };
    if section_entry_size < minimum_entry_size {
        return Err("ELF section entry is truncated".to_owned());
    }
    if section_name_index >= section_count {
        return Err("ELF section-name table index is out of bounds".to_owned());
    }

    let table_size = section_entry_size
        .checked_mul(section_count)
        .ok_or_else(|| "ELF section table size overflows".to_owned())?;
    let table_end = section_offset
        .checked_add(table_size)
        .ok_or_else(|| "ELF section table end overflows".to_owned())?;
    if table_end > bytes.len() as u64 {
        return Err("ELF section table is truncated".to_owned());
    }

    let mut raw_sections = Vec::with_capacity(section_count as usize);
    for index in 0..section_count {
        let entry_offset = section_offset
            .checked_add(section_entry_size * index)
            .ok_or_else(|| "ELF section entry offset overflows".to_owned())?;
        let entry_offset = usize::try_from(entry_offset)
            .map_err(|_| "ELF section entry offset does not fit usize".to_owned())?;
        let (name_offset, section_type, data_offset, data_size) = match class {
            ElfClass::Class32 => (
                read_u32(bytes, entry_offset, endianness)?,
                read_u32(bytes, entry_offset + 4, endianness)?,
                read_u32(bytes, entry_offset + 16, endianness)? as u64,
                read_u32(bytes, entry_offset + 20, endianness)? as u64,
            ),
            ElfClass::Class64 => (
                read_u32(bytes, entry_offset, endianness)?,
                read_u32(bytes, entry_offset + 4, endianness)?,
                read_u64(bytes, entry_offset + 24, endianness)?,
                read_u64(bytes, entry_offset + 32, endianness)?,
            ),
        };
        let data_offset = usize::try_from(data_offset)
            .map_err(|_| "ELF section offset does not fit usize".to_owned())?;
        let data_size = usize::try_from(data_size)
            .map_err(|_| "ELF section size does not fit usize".to_owned())?;
        if section_type != SHT_NOBITS
            && data_offset
                .checked_add(data_size)
                .is_none_or(|end| end > bytes.len())
        {
            return Err("ELF section data is truncated".to_owned());
        }
        raw_sections.push((name_offset, section_type, data_offset, data_size));
    }

    let (_, _, name_table_offset, name_table_size) = raw_sections[section_name_index as usize];
    if name_table_offset
        .checked_add(name_table_size)
        .is_none_or(|end| end > bytes.len())
    {
        return Err("ELF section-name table is truncated".to_owned());
    }
    let name_table = &bytes[name_table_offset..name_table_offset + name_table_size];
    let mut sections = Vec::with_capacity(raw_sections.len());
    for (name_offset, section_type, data_offset, data_size) in raw_sections {
        let name_offset = usize::try_from(name_offset)
            .map_err(|_| "ELF section name offset does not fit usize".to_owned())?;
        let name = read_string_table_entry(name_table, name_offset)?;
        sections.push(ElfSection {
            name,
            section_type,
            offset: data_offset,
            size: data_size,
        });
    }

    Ok(ElfFile {
        class,
        endianness,
        sections,
    })
}

fn read_string_table_entry(table: &[u8], offset: usize) -> Result<String, String> {
    if offset >= table.len() {
        return Err("ELF section name offset is out of bounds".to_owned());
    }
    let end = table[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|relative| offset + relative)
        .ok_or_else(|| "ELF section name is not terminated".to_owned())?;
    Ok(String::from_utf8_lossy(&table[offset..end]).into_owned())
}

fn extract_rustc_versions(bytes: &[u8], elf: &ElfFile) -> Vec<String> {
    let mut versions = BTreeSet::new();
    for section in &elf.sections {
        if section.name != ".comment" || section.section_type == SHT_NOBITS {
            continue;
        }
        let Some(end) = section.offset.checked_add(section.size) else {
            continue;
        };
        let Some(contents) = bytes.get(section.offset..end) else {
            continue;
        };
        for record in contents.split(|byte| *byte == 0) {
            let Ok(record) = std::str::from_utf8(record) else {
                continue;
            };
            let Some(version) = record.strip_prefix("rustc version ") else {
                continue;
            };
            let version = clean_display(version.trim());
            if !version.is_empty() {
                versions.insert(version);
            }
        }
    }
    versions.into_iter().collect()
}

fn provenance_report(info: &VersionInfo) -> (ProvenanceReport, Vec<Discrepancy>) {
    let packages = info
        .packages
        .iter()
        .map(|package| PackageReport {
            name: clean_display(&package.name),
            version: package.version.to_string(),
            source_claim: source_claim(&package.source),
            kind: dependency_kind(&package.kind),
            root: package.root,
            dependencies: package.dependencies.clone(),
        })
        .collect::<Vec<_>>();
    let discrepancies = analyze_packages(&info.packages);
    (
        ProvenanceReport {
            state: ClaimState::Exact,
            confidence: ClaimState::Exact,
            format_revision: Some(info.format),
            source: Some(".dep-v0".to_owned()),
            packages,
        },
        discrepancies,
    )
}

fn analyze_packages(packages: &[auditable_serde::Package]) -> Vec<Discrepancy> {
    let mut discrepancies = Vec::new();
    let mut identities: BTreeMap<(String, String, String), Vec<usize>> = BTreeMap::new();
    let mut versions_by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut sources_by_name_version: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for (index, package) in packages.iter().enumerate() {
        let name = package.name.clone();
        let version = package.version.to_string();
        let source = source_identity(&package.source);
        identities
            .entry((name.clone(), version.clone(), source.clone()))
            .or_default()
            .push(index);
        versions_by_name
            .entry(name.clone())
            .or_default()
            .insert(version.clone());
        sources_by_name_version
            .entry((name.clone(), version.clone()))
            .or_default()
            .insert(source);
        for dependency in &package.dependencies {
            if *dependency >= packages.len() {
                discrepancies.push(Discrepancy {
                    kind: "invalid-dependency-index".to_owned(),
                    package: Some(clean_display(&name)),
                    detail: format!("record {index} references package index {dependency}"),
                });
            }
        }
    }

    for ((name, version, source), indices) in identities {
        if indices.len() > 1 {
            discrepancies.push(Discrepancy {
                kind: "duplicate-record".to_owned(),
                package: Some(clean_display(&name)),
                detail: format!(
                    "{} {} from {} appears at record indices {}",
                    name,
                    version,
                    source,
                    indices
                        .iter()
                        .map(usize::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
    }
    for (name, versions) in versions_by_name {
        if versions.len() > 1 {
            discrepancies.push(Discrepancy {
                kind: "version-mismatch".to_owned(),
                package: Some(clean_display(&name)),
                detail: format!(
                    "package has versions {}",
                    versions.into_iter().collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }
    for ((name, version), sources) in sources_by_name_version {
        if sources.len() > 1 {
            discrepancies.push(Discrepancy {
                kind: "source-mismatch".to_owned(),
                package: Some(clean_display(&name)),
                detail: format!(
                    "{} {} has source claims {}",
                    name,
                    version,
                    sources.into_iter().collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }
    discrepancies
}

fn compiler_report(versions: &[String]) -> CompilerReport {
    CompilerReport {
        state: ClaimState::Exact,
        confidence: ClaimState::Exact,
        value: (versions.len() == 1).then(|| versions[0].clone()),
        versions: versions.to_vec(),
        source: Some("ELF .comment".to_owned()),
    }
}

fn missing_compiler_report() -> CompilerReport {
    CompilerReport {
        state: ClaimState::Missing,
        confidence: ClaimState::Missing,
        value: None,
        versions: Vec::new(),
        source: None,
    }
}

fn unresolved_compiler_report() -> CompilerReport {
    CompilerReport {
        state: ClaimState::Unresolved,
        confidence: ClaimState::Unresolved,
        value: None,
        versions: Vec::new(),
        source: None,
    }
}

fn missing_provenance_report() -> ProvenanceReport {
    ProvenanceReport {
        state: ClaimState::Missing,
        confidence: ClaimState::Missing,
        format_revision: None,
        source: None,
        packages: Vec::new(),
    }
}

fn unresolved_provenance_report() -> ProvenanceReport {
    ProvenanceReport {
        state: ClaimState::Unresolved,
        confidence: ClaimState::Unresolved,
        format_revision: None,
        source: None,
        packages: Vec::new(),
    }
}

fn dependency_kind(kind: &DependencyKind) -> String {
    match kind {
        DependencyKind::Build => "build".to_owned(),
        DependencyKind::Runtime => "runtime".to_owned(),
    }
}

fn source_identity(source: &Source) -> String {
    match source {
        Source::CratesIo => "crates.io".to_owned(),
        Source::Git => "git".to_owned(),
        Source::Local => "local".to_owned(),
        Source::Registry => "registry".to_owned(),
        Source::Other(_) => "other".to_owned(),
        _ => "other".to_owned(),
    }
}

fn source_claim(source: &Source) -> String {
    source_identity(source)
}

fn read_u16(bytes: &[u8], offset: usize, endianness: Endianness) -> Result<u16, String> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "ELF field is truncated".to_owned())?;
    Ok(match endianness {
        Endianness::Little => u16::from_le_bytes([raw[0], raw[1]]),
        Endianness::Big => u16::from_be_bytes([raw[0], raw[1]]),
    })
}

fn read_u32(bytes: &[u8], offset: usize, endianness: Endianness) -> Result<u32, String> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "ELF field is truncated".to_owned())?;
    Ok(match endianness {
        Endianness::Little => u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        Endianness::Big => u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
    })
}

fn read_u64(bytes: &[u8], offset: usize, endianness: Endianness) -> Result<u64, String> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| "ELF field is truncated".to_owned())?;
    Ok(match endianness {
        Endianness::Little => u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]),
        Endianness::Big => u64::from_be_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]),
    })
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn state_value(state: ClaimState) -> &'static str {
    match state {
        ClaimState::Exact => "exact",
        ClaimState::Inferred => "inferred",
        ClaimState::Missing => "missing",
        ClaimState::Unresolved => "unresolved",
    }
}

fn optional_value(value: Option<&str>) -> String {
    value.unwrap_or("none").to_owned()
}

fn clean_display(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

fn is_windows_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;
    fn package(name: &str, version: &str, source: Source, root: bool) -> auditable_serde::Package {
        auditable_serde::Package {
            name: name.to_owned(),
            version: version.parse().expect("test version"),
            source,
            kind: DependencyKind::Runtime,
            dependencies: Vec::new(),
            root,
        }
    }

    #[test]
    fn reports_duplicate_records() {
        let packages = vec![
            package("app", "1.0.0", Source::Local, true),
            package("dep", "1.0.0", Source::CratesIo, false),
            package("dep", "1.0.0", Source::CratesIo, false),
        ];
        let discrepancies = analyze_packages(&packages);
        assert!(
            discrepancies
                .iter()
                .any(|item| item.kind == "duplicate-record")
        );
    }

    #[test]
    fn reports_version_mismatch() {
        let packages = vec![
            package("app", "1.0.0", Source::Local, true),
            package("dep", "1.0.0", Source::CratesIo, false),
            package("dep", "2.0.0", Source::CratesIo, false),
        ];
        let discrepancies = analyze_packages(&packages);
        assert!(
            discrepancies
                .iter()
                .any(|item| item.kind == "version-mismatch")
        );
    }

    #[test]
    fn reports_source_mismatch() {
        let packages = vec![
            package("app", "1.0.0", Source::Local, true),
            package("dep", "1.0.0", Source::CratesIo, false),
            package("dep", "1.0.0", Source::Git, false),
        ];
        let discrepancies = analyze_packages(&packages);
        assert!(
            discrepancies
                .iter()
                .any(|item| item.kind == "source-mismatch")
        );
    }

    #[test]
    fn redacts_absolute_paths() {
        assert_eq!(
            redact_path("/home/private/build/output"),
            "<absolute>/output"
        );
        assert_eq!(redact_path("relative/output"), "relative/output");
    }

    #[test]
    fn identifies_oversized_input_before_parsing() {
        let bytes = vec![0; MAX_BINARY_BYTES + 1];
        let report = inspect_bytes("large", &bytes);
        assert_eq!(report.status, "unresolved");
        assert_eq!(report.exit_code(), 3);
    }

    #[test]
    fn renders_stable_json() {
        let report = inspect_bytes("fixture", b"not a binary");
        assert_eq!(
            render_json(&report).expect("json"),
            render_json(&report).expect("json")
        );
    }

    #[test]
    fn distinguishes_valid_elf_without_claims() {
        let mut bytes = vec![0; 64];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;

        let report = inspect_bytes("stripped", &bytes);
        assert!(report.parsed);
        assert_eq!(report.compiler.state, ClaimState::Missing);
        assert_eq!(report.provenance.state, ClaimState::Missing);
    }
}
