//! Parser for the Text-Based Stub (`.tbd`) library definitions used by Mach-O.
//!
//! This crate currently targets TBD format version 4 and extracts the
//! linker-visible symbol definitions (and weak symbols). To keep parsing
//! simple and efficient, the parser rejects escape sequences and returns
//! `&'data str` slices directly from the input.
//!
//! The parser accepts multi-document YAML TBD files. The first document is
//! treated as the main library. Additional documents are treated as child
//! libraries reexported by the main library. This covers a practical subset of
//! the full TBD v4 format, including the shape used by most system libraries.

use crate::ensure;
use crate::error;
use crate::error::Result;
use itertools::Itertools;
use serde::Deserialize;
use std::collections::HashSet;

const ARM64_LIB_ARCH: &str = "arm64e-macos";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
struct TextBasedDefinition<'a> {
    tbd_version: u32,
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(borrow)]
    install_name: &'a str,
    #[serde(default)]
    current_version: &'a str,
    #[serde(default)]
    compatibility_version: &'a str,
    #[serde(default)]
    parent_umbrella: Vec<ParentUmbrella<'a>>,
    #[serde(default)]
    reexported_libraries: Vec<ReexportedLibraries<'a>>,
    #[serde(default)]
    exports: Vec<Exports<'a>>,
    #[serde(default)]
    reexports: Vec<Exports<'a>>,
}

impl<'a> TextBasedDefinition<'a> {
    fn all_exports(&self) -> impl Iterator<Item = &Exports<'a>> {
        self.exports.iter().chain(&self.reexports)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
struct ParentUmbrella<'a> {
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(borrow)]
    umbrella: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
struct ReexportedLibraries<'a> {
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(borrow)]
    libraries: Vec<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
struct Exports<'a> {
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(default)]
    #[serde(borrow)]
    symbols: Vec<&'a str>,
    #[serde(default)]
    #[serde(borrow)]
    weak_symbols: Vec<&'a str>,
    /// Objective-C classes. A class is named once here and stands for the several symbols it
    /// actually defines, which the linker is expected to form itself.
    #[serde(default)]
    #[serde(borrow)]
    objc_classes: Vec<&'a str>,
    /// Instance variables, named `Class.ivar`.
    #[serde(default)]
    #[serde(borrow)]
    objc_ivars: Vec<&'a str>,
    /// Classes that can be thrown and caught across an image boundary.
    #[serde(default)]
    #[serde(borrow)]
    objc_eh_types: Vec<&'a str>,
    /// Variables with one instance per thread. They are named and referred to exactly as any other
    /// symbol is - what makes them thread-local is how the defining image lays them out, not
    /// anything the referring image says - so they are simply more of what the library defines.
    #[serde(default)]
    #[serde(borrow)]
    thread_local_symbols: Vec<&'a str>,
}
// TODO: remove
#[allow(unused)]
#[derive(Debug, Clone)]
pub(crate) struct DefinedStubLibrary<'a> {
    /// Install name of the dynamic library, including its `.dylib` suffix.    
    pub(crate) install_name: &'a str,
    /// Current version recorded for the library, if present.
    pub(crate) current_version: &'a str,
    /// The oldest version of the library an image linked against this one will accept. Absent
    /// means 1.0, which is what the format says and what a library that never broke
    /// compatibility gets.
    pub(crate) compatibility_version: &'a str,
    /// Global symbols defined by the library or by any reexported child library.
    pub(crate) symbols: Vec<&'a str>,
    /// Weak symbols defined by the library or by any reexported child library.
    pub(crate) weak_symbols: Vec<&'a str>,
    /// The install names of libraries this one passes on the exports of. What they define counts
    /// as defined by this library, so they have to be read too - `Foundation` re-exports
    /// `CoreFoundation` and `libobjc`, and most of what an Objective-C program refers to is in
    /// those rather than in `Foundation` itself.
    pub(crate) reexported_libraries: Vec<&'a str>,
}

impl DefinedStubLibrary<'_> {
    pub(crate) fn total_symbols(&self) -> usize {
        self.symbols.len() + self.weak_symbols.len()
    }
}

/// Which block sequence the lines being read belong to.
enum Section {
    /// Not inside one, or inside one whose contents we have no use for.
    Ignored,
    ParentUmbrella,
    ReexportedLibraries,
    Exports,
    Reexports,
}

/// Reads the shape of TBD that Apple's tooling actually emits, without a YAML parser.
///
/// A link reads well over a megabyte of these files: `-lSystem` alone names forty-six more by
/// re-export, so every C, C++ and Rust link on the platform pays for all of them before it has
/// looked at a single object. A general YAML parser spends that budget allocating a token for
/// every scalar, and the files are machine-generated and regular enough not to need one.
///
/// `None` means the file isn't the shape this understands, and the caller reads it with the real
/// parser instead. Being narrow is the point - this is only ever a fast path, and never the
/// authority on what the format means.
fn scan_tbd(input: &str) -> Option<Vec<TextBasedDefinition<'_>>> {
    let mut documents: Vec<TextBasedDefinition<'_>> = Vec::new();
    let mut section = Section::Ignored;
    let mut position = 0;

    while position < input.len() {
        let line_end = input[position..]
            .find('\n')
            .map_or(input.len(), |offset| position + offset);
        let line = &input[position..line_end];
        let content = line.trim_start();
        let indent = line.len() - content.len();
        let content = content.trim_end();

        if content.is_empty() || content.starts_with('#') {
            position = line_end + 1;
            continue;
        }

        if let Some(tag) = content.strip_prefix("---") {
            // Only the one document tag, so a file using any other shape goes to the real parser.
            if !tag.trim().is_empty() && tag.trim() != "!tapi-tbd" {
                return None;
            }
            documents.push(TextBasedDefinition::default());
            section = Section::Ignored;
            position = line_end + 1;
            continue;
        }

        if content == "..." {
            position = line_end + 1;
            continue;
        }

        // Everything else is `key: value`, possibly opening a sequence item with a leading dash.
        let (is_new_item, content) = match content.strip_prefix("- ") {
            Some(rest) => (true, rest.trim_start()),
            None => (false, content),
        };
        let colon = content.find(':')?;
        let key = &content[..colon];
        if key.is_empty() || key.contains(['\'', '"', ' ']) {
            return None;
        }

        // The value can run past the end of the line, so reading it is what advances us.
        let value_start = position + (line.len() - content.len()) + colon + 1;
        let (value, next) = read_value(input, value_start)?;
        position = next + 1;

        let document = documents.last_mut()?;

        if indent == 0 {
            if is_new_item {
                return None;
            }

            section = Section::Ignored;

            match key {
                "tbd-version" => document.tbd_version = value.parse().ok()?,
                "targets" => document.targets = parse_flow_sequence(value)?,
                "install-name" => document.install_name = unquote(value)?,
                "current-version" => document.current_version = unquote(value)?,
                "compatibility-version" => document.compatibility_version = unquote(value)?,
                "parent-umbrella" => section = Section::ParentUmbrella,
                "reexported-libraries" => section = Section::ReexportedLibraries,
                "exports" => section = Section::Exports,
                "reexports" => section = Section::Reexports,
                // An unrecognised key is ignored, which is what deserialising does with one too.
                _ => {}
            }

            // A key we know introduces a sequence, so anything on the same line isn't one.
            if !matches!(section, Section::Ignored) && !value.is_empty() {
                return None;
            }

            continue;
        }

        match section {
            Section::Ignored => {}
            Section::ParentUmbrella => {
                if is_new_item {
                    document.parent_umbrella.push(ParentUmbrella::default());
                }
                let item = document.parent_umbrella.last_mut()?;
                match key {
                    "targets" => item.targets = parse_flow_sequence(value)?,
                    "umbrella" => item.umbrella = unquote(value)?,
                    _ => {}
                }
            }
            Section::ReexportedLibraries => {
                if is_new_item {
                    document
                        .reexported_libraries
                        .push(ReexportedLibraries::default());
                }
                let item = document.reexported_libraries.last_mut()?;
                match key {
                    "targets" => item.targets = parse_flow_sequence(value)?,
                    "libraries" => item.libraries = parse_flow_sequence(value)?,
                    _ => {}
                }
            }
            Section::Exports | Section::Reexports => {
                let list = if matches!(section, Section::Exports) {
                    &mut document.exports
                } else {
                    &mut document.reexports
                };
                if is_new_item {
                    list.push(Exports::default());
                }
                let item = list.last_mut()?;
                match key {
                    "targets" => item.targets = parse_flow_sequence(value)?,
                    "symbols" => item.symbols = parse_flow_sequence(value)?,
                    "weak-symbols" => item.weak_symbols = parse_flow_sequence(value)?,
                    "objc-classes" => item.objc_classes = parse_flow_sequence(value)?,
                    "objc-ivars" => item.objc_ivars = parse_flow_sequence(value)?,
                    "objc-eh-types" => item.objc_eh_types = parse_flow_sequence(value)?,
                    "thread-local-symbols" => {
                        item.thread_local_symbols = parse_flow_sequence(value)?;
                    }
                    _ => {}
                }
            }
        }
    }

    Some(documents)
}

/// Reads what follows a `key:`, returning it and where it ended.
///
/// A flow sequence is followed to its closing bracket however many lines that takes, which is what
/// keeps the caller line-oriented: it never sees the continuation of a value as a line of its own.
fn read_value(input: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = input.as_bytes();
    let mut index = start;

    while index < input.len() && (bytes[index] == b' ' || bytes[index] == b'\t') {
        index += 1;
    }

    if index >= input.len() || bytes[index] == b'\n' {
        return Some(("", index));
    }

    if bytes[index] == b'[' {
        let mut depth = 0usize;
        let mut quote = None;
        let mut end = index;

        while end < input.len() {
            let byte = bytes[end];
            match quote {
                Some(open) => {
                    if byte == open {
                        quote = None;
                    }
                }
                None => match byte {
                    b'\'' | b'"' => quote = Some(byte),
                    b'[' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some((&input[index..=end], end + 1));
                        }
                    }
                    _ => {}
                },
            }
            end += 1;
        }

        // Ran out of input with the sequence still open.
        return None;
    }

    let end = input[index..]
        .find('\n')
        .map_or(input.len(), |offset| index + offset);
    let value = input[index..end].trim_end();

    // A `#` here would start a comment, which would mean the value isn't what it looks like.
    if value.contains('#') {
        return None;
    }

    Some((value, end))
}

/// Splits `[ a, b, c ]` into its elements, each a slice of the original input.
fn parse_flow_sequence(value: &str) -> Option<Vec<&str>> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    let mut elements = Vec::new();
    let mut quote = None;
    let mut start = 0;

    for (index, byte) in inner.bytes().enumerate() {
        match quote {
            Some(open) => {
                if byte == open {
                    quote = None;
                }
            }
            None => match byte {
                b'\'' | b'"' => quote = Some(byte),
                b',' => {
                    let element = inner[start..index].trim();
                    // Nothing between two commas isn't something the format produces, and YAML
                    // rejects it, so refusing keeps us from reading a file it wouldn't.
                    if element.is_empty() {
                        return None;
                    }
                    elements.push(unquote(element)?);
                    start = index + 1;
                }
                _ => {}
            },
        }
    }

    if quote.is_some() {
        return None;
    }

    let last = inner[start..].trim();
    if last.is_empty() {
        // Only an entirely empty sequence legitimately ends with nothing in hand; anything else
        // means a trailing comma, which again is not ours to interpret.
        if !elements.is_empty() {
            return None;
        }
    } else {
        elements.push(unquote(last)?);
    }

    Some(elements)
}

/// Strips the quotes from a scalar, refusing any that would need rewriting to read.
///
/// The elements handed back borrow from the input, so a value that isn't already the text it
/// denotes - anything with an escape in it - has nowhere to live and is refused instead.
fn unquote(value: &str) -> Option<&str> {
    if let Some(rest) = value.strip_prefix('\'') {
        let inner = rest.strip_suffix('\'')?;
        // A single quote inside is written by doubling it, so the text isn't the value.
        if inner.contains('\'') {
            return None;
        }
        return Some(inner);
    }

    if let Some(rest) = value.strip_prefix('"') {
        let inner = rest.strip_suffix('"')?;
        if inner.contains(['\\', '"']) {
            return None;
        }
        return Some(inner);
    }

    if value.contains(['#', '\'', '"']) || value.starts_with(['&', '*', '!', '{', '}']) {
        return None;
    }

    Some(value)
}

pub fn parse_defined_library<'data>(
    input: &'data str,
    symbol_names: &'data colosseum::sync::Arena<String>,
) -> Result<DefinedStubLibrary<'data>> {
    // Read it directly if it has the shape the system libraries are written in, and fall back to
    // a real YAML parser for anything else.
    let library_definitions = match scan_tbd(input) {
        Some(definitions) => definitions,
        None => serde_yaml::Deserializer::from_str(input)
            .map(TextBasedDefinition::deserialize)
            .collect::<Result<Vec<_>, _>>()?,
    };

    let main_library = library_definitions
        .first()
        .ok_or_else(|| error!("root library must be defined"))?;
    ensure!(
        main_library.targets.contains(&ARM64_LIB_ARCH),
        "Library only supports {targets:?}, but we need {ARM64_LIB_ARCH}",
        targets = main_library.targets,
    );

    // `current-version` is optional: the format says an absent one means 1.0, which is what a
    // library that has never revised itself carries anyway. Requiring it turned every library that
    // left it out into a link failure.
    let mut defined_library = DefinedStubLibrary {
        install_name: main_library.install_name,
        current_version: main_library.current_version,
        compatibility_version: main_library.compatibility_version,
        symbols: Vec::with_capacity(
            library_definitions
                .iter()
                .flat_map(TextBasedDefinition::all_exports)
                .map(|exp| exp.symbols.len())
                .sum(),
        ),
        reexported_libraries: Vec::new(),
        weak_symbols: Vec::with_capacity(
            library_definitions
                .iter()
                .flat_map(TextBasedDefinition::all_exports)
                .map(|exp| exp.weak_symbols.len())
                .sum(),
        ),
    };

    // Main libraries commonly reexport symbols from child libraries. This parser
    // currently supports only a flat tree: one main library with leaf children.
    let exported_libraries = if let Some(exported_libraries) = main_library
        .reexported_libraries
        .iter()
        .at_most_one()
        .map_err(|_| error!("expected just a single exported library"))?
    {
        ensure!(
            exported_libraries.targets.contains(&ARM64_LIB_ARCH),
            "Exported library only supports {:?}, but we need {ARM64_LIB_ARCH}",
            exported_libraries.targets
        );
        let exported_libraries: HashSet<_> = exported_libraries.libraries.iter().copied().collect();
        exported_libraries
    } else {
        HashSet::new()
    };

    // A library named here that isn't also a document in this file is a separate file to go and
    // read. The two cases look the same in the format and are told apart by what turns up.
    let own_install_names: HashSet<_> = library_definitions
        .iter()
        .map(|lib| lib.install_name)
        .collect();

    defined_library.reexported_libraries = exported_libraries
        .iter()
        .filter(|name| !own_install_names.contains(*name))
        .copied()
        .collect();

    for lib in &library_definitions {
        ensure!(
            lib.tbd_version == 4,
            "TBD version 4 expected, got {}",
            lib.tbd_version
        );
        if lib != main_library {
            ensure!(
                exported_libraries.contains(lib.install_name),
                "child library '{}' not listed as reexported by the main library",
                lib.install_name
            );
        }

        for export in lib.all_exports() {
            if export.targets.contains(&ARM64_LIB_ARCH) {
                defined_library.symbols.extend(export.symbols.iter());
                defined_library
                    .weak_symbols
                    .extend(export.weak_symbols.iter());
                defined_library
                    .symbols
                    .extend(export.thread_local_symbols.iter());

                // An Objective-C class is listed by its bare name and stands for several symbols:
                // the class itself, the metaclass behind it, and - if it can cross an image
                // boundary in a throw - its exception type. A reference from an object names one of
                // those in full, so they have to be formed here or nothing referring to a class
                // from a system library resolves.
                for class in &export.objc_classes {
                    for prefix in ["_OBJC_CLASS_$_", "_OBJC_METACLASS_$_"] {
                        defined_library
                            .symbols
                            .push(symbol_names.alloc(format!("{prefix}{class}")));
                    }
                }

                for ivar in &export.objc_ivars {
                    defined_library
                        .symbols
                        .push(symbol_names.alloc(format!("_OBJC_IVAR_$_{ivar}")));
                }

                for class in &export.objc_eh_types {
                    defined_library
                        .symbols
                        .push(symbol_names.alloc(format!("_OBJC_EHTYPE_$_{class}")));
                }
            }
        }
    }

    Ok(defined_library)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_library_with_reexports() {
        let symbol_names = colosseum::sync::Arena::new();
        let stub_library = parse_defined_library(
            r"--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64e-macos ]
install-name:    '/usr/lib/libMain.dylib'
current-version: 1.2.3
reexported-libraries:
  - targets:         [ x86_64-macos, arm64e-macos ]
    libraries:       [ '/usr/lib/libA.dylib', '/usr/lib/libB.dylib' ]
exports:
  - targets:         [ arm64e-macos ]
    symbols:         [ _main_arm64 ]
    weak-symbols:    [ _main_weak_arm64 ]
  - targets:         [ x86_64-macos ]
    symbols:         [ _main_x86_64 ]
    weak-symbols:    [ _main_weak_x86_64 ]
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64e-macos ]
install-name:    '/usr/lib/libA.dylib'
current-version: 10
parent-umbrella:
  - targets:         [ x86_64-macos, arm64e-macos ]
    umbrella:        Main
exports:
  - targets:         [ arm64e-macos ]
    symbols:         [ _a_arm64 ]
    weak-symbols:    [ _a_weak_arm64 ]
  - targets:         [ x86_64-macos ]
    symbols:         [ _a_x86_64 ]
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64e-macos ]
install-name:    '/usr/lib/libB.dylib'
current-version: 11
parent-umbrella:
  - targets:         [ x86_64-macos, arm64e-macos ]
    umbrella:        Main
exports:
  - targets:         [ arm64e-macos ]
    symbols:         [ _b_arm64 ]
reexports:
  - targets:         [ arm64e-macos ]
    symbols:         [ _b_exported_arm64 ]
    weak-symbols:    [ _b_weak_exported_arm64 ]
",
            &symbol_names,
        )
        .expect("definition should parse");

        assert_eq!(stub_library.install_name, "/usr/lib/libMain.dylib");
        assert_eq!(stub_library.current_version, "1.2.3");
        assert_eq!(
            stub_library.symbols,
            ["_main_arm64", "_a_arm64", "_b_arm64", "_b_exported_arm64"]
        );
        assert_eq!(
            stub_library.weak_symbols,
            [
                "_main_weak_arm64",
                "_a_weak_arm64",
                "_b_weak_exported_arm64"
            ]
        );
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;

    /// Reads every stub library the installed SDK ships with, both ways, and requires the fast one
    /// to either agree exactly or refuse the file.
    ///
    /// The corpus is the point: several thousand machine-generated files is a far better account of
    /// what the format does in practice than any set of examples written by hand.
    #[test]
    fn scanner_agrees_with_yaml_across_the_sdk() {
        let Ok(output) = std::process::Command::new("xcrun")
            .args(["--show-sdk-path"])
            .output()
        else {
            return;
        };
        let sdk = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if sdk.is_empty() || !std::path::Path::new(&sdk).exists() {
            return;
        }

        let mut checked = 0;
        let mut declined = 0;
        let mut tolerated = 0;
        let mut stack = vec![std::path::PathBuf::from(&sdk)];

        while let Some(directory) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "tbd") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };

                let yaml = serde_yaml::Deserializer::from_str(&text)
                    .map(TextBasedDefinition::deserialize)
                    .collect::<Result<Vec<_>, _>>();

                match (scan_tbd(&text), yaml) {
                    (Some(scanned), Ok(parsed)) => {
                        assert_eq!(scanned, parsed, "disagreed on {}", path.display());
                        checked += 1;
                    }
                    // Refusing a file is always allowed - the caller falls back.
                    (None, _) => declined += 1,
                    // Reading a file the YAML parser won't is allowed too, and is the point of
                    // being narrow rather than strict: `WeatherResources.tbd` has an empty element
                    // in a list we have no use for, which YAML rejects outright and `ld` reads
                    // without complaint. Skipping what we don't need means we agree with `ld`.
                    (Some(_), Err(_)) => tolerated += 1,
                }
            }
        }

        assert!(
            checked > 100,
            "expected an SDK with stub libraries, read {checked}"
        );
        println!(
            "{checked} agreed, {declined} declined to YAML, {tolerated} read that YAML rejects"
        );
    }
}
