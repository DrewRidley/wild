//! Differential check of Apple's `dyld_info` output between our binary and the reference
//! linker's. Independent of both libwild and of the in-tree chained-fixups parser.
//!
//! This module deliberately does *not* parse any Mach-O structure itself. It shells out to
//! Apple's own tools and compares their rendering of our output against their rendering of the
//! reference linker's output. That makes it a genuinely independent oracle: it shares no code,
//! and no assumptions, with the linker under test.
//!
//! Three checks are performed, all under the `macho.dyld-info.*` key namespace:
//!
//! * `macho.dyld-info.fixups` - `dyld_info -fixups`, the list of load-time fixups.
//! * `macho.dyld-info.exports` - `dyld_info -exports`, the exports trie.
//! * `macho.dyld-info.chain-starts` - `otool -fixup_chains`, the structural view of
//!   `LC_DYLD_CHAINED_FIXUPS`. This is deliberately kept even though it overlaps `-fixups`, because
//!   `dyld_info` *crashes* on some malformed inputs (see below) whereas `otool` keeps printing, so
//!   the two together degrade gracefully in opposite directions.
//! * `macho.dyld-info.tool-missing` - reported if the tools can't be found at all. A missing tool
//!   is a loud diff, never a silent pass.
//!
//! # Normalisation rules
//!
//! Anything a linker may legitimately choose differently is removed:
//!
//! * absolute and image-relative addresses (segment base addresses differ - wild puts `__DATA` at
//!   `+0x4000` and ld64 puts it at `+0x8000`, both correct),
//! * segment *indexes* (segment order differs between the two linkers),
//! * `LINKEDIT` offsets/sizes inside the chained-fixups blob.
//!
//! What is never removed is the **presence or absence of a record**. That is the bug class this
//! module exists to catch: wild currently emits zero rebases for a program where ld64 emits one,
//! and the resulting binary segfaults.
//!
//! All comparison lines are guaranteed free of `0x`-prefixed hex literals, because the
//! integration-test snapshot normaliser deletes any report line containing three or more hex
//! digits.

use crate::Binary;
use crate::Diff;
use crate::DiffValues;
use crate::Report;
use object::Object as _;
use object::ObjectSection as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DyldInfoMode {
    Fixups,
    Exports,
}

impl DyldInfoMode {
    fn flag(self) -> &'static str {
        match self {
            DyldInfoMode::Fixups => "-fixups",
            DyldInfoMode::Exports => "-exports",
        }
    }

    fn key(self) -> &'static str {
        match self {
            DyldInfoMode::Fixups => "macho.dyld-info.fixups",
            DyldInfoMode::Exports => "macho.dyld-info.exports",
        }
    }
}

/// Outcome of one external-tool invocation. A crash is DATA, not an error to swallow.
pub(crate) enum ToolOutcome {
    Ok(String),
    /// Non-zero exit. `status` is the raw `ExitStatus` rendering, e.g. "signal: 11 (SIGSEGV)".
    Failed {
        status: String,
        stderr: String,
    },
    /// Tool not on PATH - the whole pass is skipped (reported once, loudly, as a diff key
    /// `macho.dyld-info.tool-missing`, NOT as a silent pass).
    Unavailable,
}

impl ToolOutcome {
    /// A one-line rendering used as the per-object value of a diff.
    fn describe(&self) -> String {
        match self {
            ToolOutcome::Ok(_) => "OK".to_owned(),
            ToolOutcome::Failed { status, stderr } => {
                let detail = stderr
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("(no stderr)");
                format!("TOOL FAILED: {status}: {detail}")
            }
            ToolOutcome::Unavailable => "TOOL UNAVAILABLE".to_owned(),
        }
    }
}

/// Resolves a tool from the active Xcode toolchain, via `xcrun --find`. Resolved once per
/// process. We never hardcode an Xcode path.
fn find_tool(name: &str) -> Option<&'static Path> {
    static DYLD_INFO: OnceLock<Option<PathBuf>> = OnceLock::new();
    static OTOOL: OnceLock<Option<PathBuf>> = OnceLock::new();

    let cell = match name {
        "dyld_info" => &DYLD_INFO,
        "otool" => &OTOOL,
        _ => return None,
    };

    cell.get_or_init(|| resolve_tool(name)).as_deref()
}

fn resolve_tool(name: &str) -> Option<PathBuf> {
    // Prefer the Xcode toolchain copy, since that's the one that matches the SDK we linked
    // against. Fall back to a bare PATH lookup.
    if let Ok(xcrun) = which::which("xcrun")
        && let Ok(output) = Command::new(xcrun).arg("--find").arg(name).output()
        && output.status.success()
    {
        let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        if path.is_file() {
            return Some(path);
        }
    }

    which::which(name).ok()
}

fn run_tool(tool: &str, args: &[&str], path: &Path) -> ToolOutcome {
    let Some(exe) = find_tool(tool) else {
        return ToolOutcome::Unavailable;
    };

    let output = match Command::new(exe).args(args).arg(path).output() {
        Ok(output) => output,
        Err(error) => {
            return ToolOutcome::Failed {
                status: "failed to spawn".to_owned(),
                stderr: error.to_string(),
            };
        }
    };

    if output.status.success() {
        ToolOutcome::Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        // This is the interesting path: `dyld_info -fixups` currently dies with SIGSEGV on
        // wild's output. If we treated that as "empty stdout" we'd normalise a crash into
        // "no fixups" and report a pass.
        ToolOutcome::Failed {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

pub(crate) fn run_dyld_info(path: &Path, mode: DyldInfoMode) -> ToolOutcome {
    run_tool("dyld_info", &[mode.flag()], path)
}

pub(crate) fn run_otool_fixup_chains(path: &Path) -> ToolOutcome {
    run_tool("otool", &["-fixup_chains"], path)
}

// ---------------------------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------------------------

/// Strips the `<path> [arch]:` banner, the `-fixups:`/`-exports:` label, the column header, and
/// every absolute address column. Returns one normalized line per record, sorted.
pub(crate) fn normalise(raw: &str, mode: DyldInfoMode) -> Vec<String> {
    match mode {
        DyldInfoMode::Fixups => normalise_fixups(raw, None),
        DyldInfoMode::Exports => normalise_exports(raw),
    }
}

fn is_hex_literal(token: &str) -> bool {
    let Some(digits) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    else {
        return false;
    };
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Replaces every `0x`-prefixed token with a placeholder. Guarantees that no comparison line
/// carries a hex address, which matters both because addresses legitimately differ between
/// linkers and because the snapshot normaliser deletes lines containing them.
fn scrub_addresses(text: &str) -> String {
    text.split_whitespace()
        .map(|token| {
            // Handle things like `_printf+0x10` and `[resolver=0x1000]`.
            if is_hex_literal(token) {
                "<addr>".to_owned()
            } else if let Some((before, after)) = token.split_once("0x") {
                let (hex, rest): (String, String) = {
                    let split = after
                        .find(|c: char| !c.is_ascii_hexdigit())
                        .unwrap_or(after.len());
                    (after[..split].to_owned(), after[split..].to_owned())
                };
                if hex.is_empty() {
                    token.to_owned()
                } else {
                    format!("{before}<addr>{rest}")
                }
            } else {
                token.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Skips the banner (`p.wild [arm64]:`), the section label (`-fixups:`) and the column header.
fn is_boilerplate(line: &str) -> bool {
    let trimmed = line.trim();

    if trimmed.is_empty() {
        return true;
    }

    // Banner. Emitted at column zero and ends with a colon.
    if !line.starts_with(' ') && trimmed.ends_with(':') {
        return true;
    }

    if trimmed == "-fixups:" || trimmed == "-exports:" {
        return true;
    }

    // Column headers.
    if trimmed.starts_with("segment ") || trimmed.starts_with("offset ") {
        return true;
    }

    false
}

/// `dyld_info -fixups` prints one record per line:
///
/// ```text
///     segment         section          address             type   target
///     __DATA_CONST    __got            0x100004000           bind  libSystem/_printf
///     __DATA          __data           0x100008008         rebase  0x100008000
/// ```
///
/// We keep segment name, section name and type verbatim. The slot address is dropped - it is
/// pure layout. For a `bind`, the target is already symbolic (`libSystem/_printf`) and is kept.
/// For a `rebase` the target is an address, which we describe by the segment/section it lands
/// in when a `Binary` is available (symmetric on both sides, so it cannot produce a one-sided
/// fallback), and scrub otherwise.
fn normalise_fixups(raw: &str, bin: Option<&Binary>) -> Vec<String> {
    let mut out = Vec::new();

    for line in raw.lines() {
        if is_boilerplate(line) {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();

        // segment, section, address, type, target...
        if tokens.len() >= 4 && is_hex_literal(tokens[2]) {
            let segment = tokens[0];
            let section = tokens[1];
            let kind = tokens[3];
            let target = tokens[4..].join(" ");

            let target = if target.is_empty() {
                String::new()
            } else if is_hex_literal(&target) {
                match bin.and_then(|bin| parse_hex(&target).map(|a| describe_address(bin, a))) {
                    Some(description) => format!(" -> {description}"),
                    None => " -> <addr>".to_owned(),
                }
            } else {
                format!(" -> {}", scrub_addresses(&target))
            };

            out.push(format!("{segment}/{section} {kind}{target}"));
        } else {
            // Unrecognised shape. Keep it rather than dropping it - dropping a record we don't
            // understand is exactly how a null oracle is built.
            out.push(scrub_addresses(line));
        }
    }

    out.sort();
    out
}

/// `dyld_info -exports` prints:
///
/// ```text
///     offset      symbol
///     0x00000000  __mh_execute_header
///     0x00008000  _g
/// ```
///
/// The offset is pure layout and is dropped. Flags such as `[weak_def]` or `[re-export]` are
/// kept, since those are semantic.
fn normalise_exports(raw: &str) -> Vec<String> {
    let mut out = Vec::new();

    for line in raw.lines() {
        if is_boilerplate(line) {
            continue;
        }

        let mut tokens: Vec<&str> = line.split_whitespace().collect();

        if tokens.first().is_some_and(|token| is_hex_literal(token)) {
            tokens.remove(0);
        }

        if tokens.is_empty() {
            continue;
        }

        // KNOWN DIFFERENCE, deliberately normalised away: ld64 exports `__mh_execute_header`
        // from executables and wild does not. That is a real (minor) wild gap, but it is
        // present on every single executable, so leaving it in would make the exports check
        // fire on every Mach-O test and drown out anything specific. It is tracked separately;
        // do not silently extend this list.
        if tokens[0] == "__mh_execute_header" {
            continue;
        }

        out.push(scrub_addresses(&tokens.join(" ")));
    }

    out.sort();
    out
}

/// `otool -fixup_chains` renders the `LC_DYLD_CHAINED_FIXUPS` payload structurally:
///
/// ```text
/// chained starts in image
///   seg_count = 5
///     seg_offset[0] = 0 (__PAGEZERO)
///     seg_offset[2] = 0 (__DATA)
///     seg_offset[3] = 24 (__DATA_CONST)
/// chained starts in segment 3 (__DATA_CONST)
///   page_size = 0x4000
///   pointer_format = 6 (DYLD_CHAINED_PTR_64_OFFSET)
///   segment_offset = 0x8000
///   page_count = 1
///     page_start[0] = 0
/// ```
///
/// We keep: which segments (**by name**) have a starts record, the pointer format, the page
/// size, how many pages, whether each page has a chain start, and the import table. We drop:
/// every offset into `__LINKEDIT` (`starts_offset`, `imports_offset`, `symbols_offset`, `size`,
/// `name_offset`), the segment *index*, and `segment_offset` - all of which legitimately differ
/// because the two linkers order and place their segments differently.
///
/// The `page_start` value itself is reduced to present/none rather than kept numerically: it is
/// a byte offset within a page, which depends on how the linker ordered variables inside a
/// section. Presence is the signal that catches a dropped rebase.
fn normalise_fixup_chains(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut segments_with_starts = Vec::new();
    let mut current_segment: Option<String> = None;
    let mut current_import: Option<usize> = None;

    for line in raw.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("chained starts in segment ") {
            // "3 (__DATA_CONST)" - keep the name, discard the index.
            current_segment = Some(bracketed_name(rest).unwrap_or("?").to_owned());
            current_import = None;
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("dyld chained import") {
            // "[0] = 0x00000001"
            current_import = rest
                .split_once('[')
                .and_then(|(_, r)| r.split_once(']'))
                .and_then(|(index, _)| index.parse::<usize>().ok())
                .or(Some(0));
            current_segment = None;
            continue;
        }

        if trimmed.starts_with("chained fixups header") || trimmed == "chained starts in image" {
            current_segment = None;
            current_import = None;
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        if let Some(index) = key.strip_prefix("seg_offset[") {
            // `seg_offset[3] = 24 (__DATA_CONST)`. A non-zero offset means "this segment has a
            // starts record". We record it by NAME - segment order differs between linkers.
            let _ = index;
            let name = bracketed_name(value).unwrap_or("?");
            let offset = value
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            if offset != 0 {
                segments_with_starts.push(name.to_owned());
            }
            continue;
        }

        if let Some(segment) = current_segment.as_deref() {
            match key {
                // `size` and `segment_offset` are layout.
                "page_size" => out.push(format!(
                    "starts {segment} page_size {}",
                    parse_number(value).unwrap_or_default()
                )),
                "pointer_format" => {
                    out.push(format!("starts {segment} pointer_format {value}"));
                }
                "max_valid_pointer" => out.push(format!(
                    "starts {segment} max_valid_pointer {}",
                    parse_number(value).unwrap_or_default()
                )),
                "page_count" => {
                    out.push(format!("starts {segment} page_count {value}"));
                }
                _ => {}
            }

            if let Some(index) = key.strip_prefix("page_start[") {
                let index = index.trim_end_matches(']');
                // DYLD_CHAINED_PTR_START_NONE == 0xFFFF.
                let present = match parse_number(value) {
                    Some(0xFFFF) | None => "none",
                    Some(_) => "present",
                };
                out.push(format!("starts {segment} page_start[{index}] {present}"));
            }

            continue;
        }

        if let Some(index) = current_import {
            match key {
                "lib_ordinal" => {
                    out.push(format!("import[{index}] lib_ordinal {value}"));
                }
                "weak_import" => {
                    out.push(format!("import[{index}] weak_import {value}"));
                }
                "name_offset" => {
                    // `0 (_printf)` - the offset is layout, the name is not.
                    let name = bracketed_name(value).unwrap_or("?");
                    out.push(format!("import[{index}] name {name}"));
                }
                _ => {}
            }
            continue;
        }

        // Header fields.
        match key {
            "fixups_version" | "imports_count" | "imports_format" | "symbols_format" => {
                out.push(format!("header {key} {value}"));
            }
            _ => {}
        }
    }

    segments_with_starts.sort();
    out.push(format!(
        "segments-with-starts: {}",
        if segments_with_starts.is_empty() {
            "(none)".to_owned()
        } else {
            segments_with_starts.join(" ")
        }
    ));

    out.sort();
    out
}

/// Extracts `foo` from `... (foo)`.
fn bracketed_name(text: &str) -> Option<&str> {
    let (_, rest) = text.rsplit_once('(')?;
    let (name, _) = rest.split_once(')')?;
    Some(name)
}

fn parse_number(text: &str) -> Option<u64> {
    let token = text.split_whitespace().next()?;
    parse_hex(token).or_else(|| token.parse::<u64>().ok())
}

fn parse_hex(text: &str) -> Option<u64> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    u64::from_str_radix(digits, 16).ok()
}

/// Describes an absolute VM address by the segment/section it lands in. Deliberately *not* by
/// symbol name and deliberately without an offset: both linkers compute this from their own
/// binary, so the answer is symmetric and layout-independent. A one-sided fallback (where one
/// linker resolves a name and the other doesn't) would produce a false positive.
fn describe_address(bin: &Binary, address: u64) -> String {
    for section in bin.file.sections() {
        let start = section.address();
        if start <= address && address < start + section.size() {
            let segment = section
                .segment_name()
                .ok()
                .flatten()
                .unwrap_or("?")
                .to_owned();
            let name = section.name().unwrap_or("?");
            return format!("{segment}/{name}");
        }
    }

    "<unmapped>".to_owned()
}

// ---------------------------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------------------------

fn is_macho(bin: &Binary) -> bool {
    matches!(
        bin.file,
        object::File::MachO32(_) | object::File::MachO64(_)
    )
}

pub(crate) fn report_diffs(report: &mut Report, objects: &[Binary]) {
    if objects.len() < 2 || !objects.iter().all(is_macho) {
        return;
    }

    let dyld_info_available = find_tool("dyld_info").is_some();
    let otool_available = find_tool("otool").is_some();

    if !dyld_info_available || !otool_available {
        let mut missing = Vec::new();
        if !dyld_info_available {
            missing.push("dyld_info");
        }
        if !otool_available {
            missing.push("otool");
        }
        report.add_diff(Diff {
            key: "macho.dyld-info.tool-missing".to_owned(),
            values: DiffValues::PreFormatted(format!(
                "Mach-O output could not be validated against Apple's tools.\n\
                 Missing (via `xcrun --find`): {}\n\
                 This is reported rather than skipped so that an unvalidated build is never \
                 mistaken for a validated one.",
                missing.join(", ")
            )),
        });
    }

    let mut diffs = Vec::new();

    if dyld_info_available {
        diffs.extend(check(
            report,
            objects,
            DyldInfoMode::Fixups.key(),
            |bin| run_dyld_info(&bin.path, DyldInfoMode::Fixups),
            |raw, bin| normalise_fixups(raw, Some(bin)),
        ));
        diffs.extend(check(
            report,
            objects,
            DyldInfoMode::Exports.key(),
            |bin| run_dyld_info(&bin.path, DyldInfoMode::Exports),
            |raw, _bin| normalise(raw, DyldInfoMode::Exports),
        ));
    }

    if otool_available {
        diffs.extend(check(
            report,
            objects,
            "macho.dyld-info.chain-starts",
            |bin| run_otool_fixup_chains(&bin.path),
            |raw, _bin| normalise_fixup_chains(raw),
        ));
    }

    report.add_diffs(diffs);
}

fn check(
    report: &Report,
    objects: &[Binary],
    key: &str,
    run: impl Fn(&Binary) -> ToolOutcome,
    normalise_fn: impl Fn(&str, &Binary) -> Vec<String>,
) -> Vec<Diff> {
    let outcomes = objects.iter().map(&run).collect::<Vec<_>>();

    // A tool failure is a first-class reported value. `dyld_info -fixups` exits 139 (SIGSEGV) on
    // wild's current output; if that didn't go red, this check would be worthless.
    if outcomes
        .iter()
        .any(|outcome| !matches!(outcome, ToolOutcome::Ok(_)))
    {
        return vec![Diff {
            key: key.to_owned(),
            values: DiffValues::PerObject(outcomes.iter().map(ToolOutcome::describe).collect()),
        }];
    }

    let normalised = outcomes
        .iter()
        .zip(objects)
        .map(|(outcome, bin)| match outcome {
            ToolOutcome::Ok(raw) => normalise_fn(raw, bin),
            _ => unreachable!("checked above"),
        })
        .collect::<Vec<_>>();

    if report.config.match_multi(normalised.iter()) {
        return vec![];
    }

    vec![Diff {
        key: key.to_owned(),
        values: DiffValues::PreFormatted(render_mismatch(objects, &normalised)),
    }]
}

/// Renders only the records that aren't common to every binary, as a multiset difference. The
/// output is intentionally free of hex addresses so that it survives the integration test
/// snapshot normaliser.
fn render_mismatch(objects: &[Binary], normalised: &[Vec<String>]) -> String {
    let mut out = String::new();

    let mut all_records = normalised.iter().flatten().cloned().collect::<Vec<_>>();
    all_records.sort();
    all_records.dedup();

    for record in &all_records {
        let counts = normalised
            .iter()
            .map(|records| records.iter().filter(|r| *r == record).count())
            .collect::<Vec<_>>();

        if counts.iter().all(|c| *c == counts[0]) {
            continue;
        }

        let present = objects
            .iter()
            .zip(&counts)
            .filter(|(_, count)| **count > 0)
            .map(|(bin, count)| {
                if *count == 1 {
                    bin.name.clone()
                } else {
                    format!("{}x{count}", bin.name)
                }
            })
            .collect::<Vec<_>>();

        let missing = objects
            .iter()
            .zip(&counts)
            .filter(|(_, count)| **count == 0)
            .map(|(bin, _)| bin.name.clone())
            .collect::<Vec<_>>();

        out.push_str(&format!("{record}\n"));
        out.push_str(&format!("    present in: {}\n", present.join(", ")));
        if !missing.is_empty() {
            out.push_str(&format!("    MISSING FROM: {}\n", missing.join(", ")));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LD64_FIXUPS: &str = "\
p.ld64 [arm64]:
    -fixups:
        segment         section          address             type   target
        __DATA_CONST    __got            0x100004000           bind  libSystem/_printf
        __DATA          __data           0x100008008         rebase  0x100008000
";

    const LD64_EXPORTS: &str = "\
p.ld64 [arm64]:
    -exports:
        offset      symbol
        0x00000000  __mh_execute_header
        0x00008000  _g
        0x000004F8  _main
        0x00008008  _pg
";

    const WILD_EXPORTS: &str = "\
p.wild [arm64]:
    -exports:
        offset      symbol
        0x00004000  _g
        0x00000440  _main
        0x00004008  _pg
";

    const WILD_CHAINS: &str = "\
p.wild:
chained fixups header (LC_DYLD_CHAINED_FIXUPS)
  fixups_version = 0
  starts_offset  = 28
  imports_offset = 76
  symbols_offset = 80
  imports_count  = 1
  imports_format = 1 (DYLD_CHAINED_IMPORT)
  symbols_format = 0
chained starts in image
  seg_count = 5
    seg_offset[0] = 0 (__PAGEZERO)
    seg_offset[1] = 0 (__TEXT)
    seg_offset[2] = 0 (__DATA)
    seg_offset[3] = 24 (__DATA_CONST)
    seg_offset[4] = 0 (__LINKEDIT)
chained starts in segment 3 (__DATA_CONST)
  size = 24
  page_size = 0x4000
  pointer_format = 6 (DYLD_CHAINED_PTR_64_OFFSET)
  segment_offset = 0x8000
  max_valid_pointer = 0
  page_count = 1
    page_start[0] = 0
dyld chained import[0] = 0x00000001
  lib_ordinal = 1 (libSystem)
  weak_import = 0
  name_offset = 0 (_printf)
";

    const LD64_CHAINS: &str = "\
p.ld64:
chained fixups header (LC_DYLD_CHAINED_FIXUPS)
  fixups_version = 0
  starts_offset  = 32
  imports_offset = 104
  symbols_offset = 108
  imports_count  = 1
  imports_format = 1 (DYLD_CHAINED_IMPORT)
  symbols_format = 0
chained starts in image
  seg_count = 5
    seg_offset[0] = 0 (__PAGEZERO)
    seg_offset[1] = 0 (__TEXT)
    seg_offset[2] = 24 (__DATA_CONST)
    seg_offset[3] = 48 (__DATA)
    seg_offset[4] = 0 (__LINKEDIT)
chained starts in segment 2 (__DATA_CONST)
  size = 24
  page_size = 0x4000
  pointer_format = 6 (DYLD_CHAINED_PTR_64_OFFSET)
  segment_offset = 0x4000
  max_valid_pointer = 0
  page_count = 1
    page_start[0] = 0
chained starts in segment 3 (__DATA)
  size = 24
  page_size = 0x4000
  pointer_format = 6 (DYLD_CHAINED_PTR_64_OFFSET)
  segment_offset = 0x8000
  max_valid_pointer = 0
  page_count = 1
    page_start[0] = 8
dyld chained import[0] = 0x00000201
  lib_ordinal = 1 (libSystem)
  weak_import = 0
  name_offset = 1 (_printf)
";

    #[test]
    fn fixups_drop_addresses_but_keep_records() {
        let lines = normalise(LD64_FIXUPS, DyldInfoMode::Fixups);
        assert_eq!(
            lines,
            vec![
                "__DATA/__data rebase -> <addr>".to_owned(),
                "__DATA_CONST/__got bind -> libSystem/_printf".to_owned(),
            ]
        );
        assert!(lines.iter().all(|line| !line.contains("0x")));
    }

    #[test]
    fn exports_drop_offsets_and_mh_execute_header() {
        assert_eq!(
            normalise(LD64_EXPORTS, DyldInfoMode::Exports),
            normalise(WILD_EXPORTS, DyldInfoMode::Exports)
        );
        assert_eq!(
            normalise(WILD_EXPORTS, DyldInfoMode::Exports),
            vec!["_g".to_owned(), "_main".to_owned(), "_pg".to_owned()]
        );
    }

    /// The live bug: wild emits a starts record for `__DATA_CONST` only, ld64 emits one for
    /// `__DATA` as well, so wild's rebase of `_pg` never happens and the binary segfaults.
    #[test]
    fn chain_starts_catch_the_missing_data_segment() {
        let wild = normalise_fixup_chains(WILD_CHAINS);
        let ld64 = normalise_fixup_chains(LD64_CHAINS);

        assert_ne!(wild, ld64);
        assert!(
            wild.contains(&"segments-with-starts: __DATA_CONST".to_owned()),
            "{wild:?}"
        );
        assert!(
            ld64.contains(&"segments-with-starts: __DATA __DATA_CONST".to_owned()),
            "{ld64:?}"
        );

        // The differing segment_offset (0x8000 vs 0x4000) and the differing LINKEDIT offsets
        // must NOT show up - those are legitimate layout differences.
        assert!(wild.iter().all(|line| !line.contains("segment_offset")));
        assert!(wild.iter().all(|line| !line.contains("starts_offset")));

        // And no hex, so the snapshot normaliser can't eat the output.
        assert!(wild.iter().all(|line| !line.contains("0x")), "{wild:?}");
    }

    #[test]
    fn identical_input_is_quiet() {
        assert_eq!(
            normalise_fixup_chains(LD64_CHAINS),
            normalise_fixup_chains(LD64_CHAINS)
        );
        assert_eq!(
            normalise(LD64_FIXUPS, DyldInfoMode::Fixups),
            normalise(LD64_FIXUPS, DyldInfoMode::Fixups)
        );
    }

    #[test]
    fn unknown_record_shapes_are_kept_not_dropped() {
        let raw = "x [arm64]:\n    -fixups:\n        something totally unexpected 0x1234\n";
        let lines = normalise(raw, DyldInfoMode::Fixups);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("unexpected"));
        assert!(!lines[0].contains("0x1234"));
    }
}
