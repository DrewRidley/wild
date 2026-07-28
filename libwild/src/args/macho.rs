use crate::alignment::MACHO_PAGE_ALIGNMENT;
use crate::args::ArgumentParser;
use crate::args::CommonArgs;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::bail;
use crate::ensure;
use crate::error::Context;
use crate::error::Result;
use crate::platform;
use crate::platform::Args;
use itertools::Itertools;
use itertools::repeat_n;
use object::macho::Version;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug)]
pub struct MachOArgs {
    pub(crate) common: super::CommonArgs,

    pub(crate) platform_version: Option<PlatformVersion>,
    pub(crate) sysroot: Option<Box<Path>>,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) plugin_path: Option<String>,
    pub(crate) dead_strip_dylibs: bool,
    pub(crate) dead_strip: bool,
    /// Emit a dylib rather than an executable.
    pub(crate) dylib: bool,
    /// The name a dylib records for itself, which is what images linking against it will look for.
    pub(crate) install_name: Option<Box<str>>,
    /// A file naming the symbols to export, one per line, instead of exporting everything visible.
    pub(crate) exported_symbols_list: Option<Box<Path>>,
    /// Directories dyld searches for `@rpath`-relative dependencies, in the order given.
    pub(crate) rpaths: Vec<Box<str>>,
    /// Where to look for frameworks, `-F` directories first and the system ones after.
    pub(crate) framework_search_path: Vec<Box<Path>>,
    /// The version this dylib declares itself to be, and the oldest one an image built against it
    /// will accept. Both default to 0.0.0, as ld64's do.
    pub(crate) current_version: Option<SemanticVersion>,
    pub(crate) compatibility_version: Option<SemanticVersion>,
    /// Symbols to resolve as though something had referenced them, from `-u`.
    pub(crate) undefined: Vec<String>,
    /// Symbols to export whatever else says otherwise, from `-exported_symbol`.
    pub(crate) exported_symbols: Vec<String>,
    /// Whether every archive member is to be loaded, referenced or not.
    pub(crate) all_load: bool,
    /// Whether to leave out the debug map, from `-S`.
    pub(crate) strip_debug: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticVersion(Version);
impl SemanticVersion {
    fn try_from(value: &str) -> Result<Self> {
        let mut parts = value.split('.').collect_vec();
        ensure!(
            !parts.is_empty() && parts.len() <= 3,
            "Wrong number of components: {}",
            value
        );
        parts.extend(repeat_n("0", 3 - parts.len()));

        Ok(Self(Version::new(
            parts[0].parse()?,
            parts[1].parse()?,
            parts[2].parse()?,
        )))
    }

    pub(crate) fn get(&self) -> Version {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlatformVersion {
    pub(crate) platform: String,
    pub(crate) minimum_version: SemanticVersion,
    pub(crate) sdk_version: SemanticVersion,
}

const SILENTLY_IGNORED_FLAGS: &[&str] = &[
    "no_deduplicate",
    // Mach-O appears to always demangle symbols.
    "demangle",
    "dynamic",
    // Diagnostics. They ask ld64 to say more about what it did; saying nothing extra is a fair
    // answer and changes nothing about the output.
    "v",
    "t",
    "w",
    "why_load",
    "whyload",
    "warn_unused_dylibs",
    "warn_compact_unwind",
    "no_warn_duplicate_libraries",
    // ld64's default since Xcode 4, and ours: a `-L` directory is searched before the system ones.
    "search_paths_first",
    // Reserve room in the header so `install_name_tool` can lengthen paths later. It costs padding
    // and buys nothing at link time; a later retrofit may find less slack than it wanted, which is
    // that tool's error to report rather than ours to pre-empt.
    "headerpad_max_install_names",
    // Strip local symbols. Keeping them only makes the symbol table larger than asked - never
    // wrong, and never something the loader reads.
    "x",
    // Marks the image as safe to use from an app extension. ld64 sets a header bit and checks the
    // APIs used against a list; we do neither, and the bit is advisory.
    "application_extension",
    "no_application_extension",
    // We emit `LC_UUID` with no meaningful content, so being asked not to identify the build
    // uniquely is already satisfied.
    "no_uuid",
    // Asking for what we already do: every image we produce is position-independent.
    "pie",
];

/// Flags that take a value and that we can disregard along with it, for the reasons above.
const SILENTLY_IGNORED_FLAGS_WITH_PARAM: &[&str] = &[
    // The name the whole (possibly multi-architecture) output will end up under. ld64 uses it only
    // to guess an install name for a dylib that wasn't given one; we require `-install_name`.
    "final_output",
    // Where to leave the object files LTO produces. We don't run LTO.
    "object_path_lto",
    // An explicit header padding size - see `headerpad_max_install_names`.
    "headerpad",
    // What to do about a symbol defined more than once. Deprecated in ld64, and our answer is
    // fixed: the first definition wins.
    "multiply_defined",
    "multiply_defined_unused",
];

/// Flags we recognise but can't honour, and why. Saying so beats "unrecognized option": the
/// difference between a flag we've never heard of and one whose meaning we can't deliver is the
/// difference between a typo and a missing feature.
const UNSUPPORTED_FLAGS: &[(&str, &str)] = &[
    ("static", "we only produce dynamically linked images"),
    ("no_pie", "we only produce position-independent images"),
    (
        "no_fixup_chains",
        "we only produce chained fixups, not the older rebase and bind opcodes",
    ),
    ("bundle", "we only produce executables and dylibs"),
    ("bundle_loader", "we only produce executables and dylibs"),
    (
        "ObjC",
        "we don't yet load archive members for the Objective-C metadata they define, and \
         quietly leaving them out would break categories at run time rather than at link time",
    ),
    (
        "undefined",
        "we always treat an unresolved symbol as an error",
    ),
    ("map", "we don't write a link map"),
    ("order_file", "we don't order functions by a supplied list"),
    ("sectcreate", "we don't add sections from a file"),
    ("filelist", "we don't read input filenames from a file"),
    (
        "unexported_symbols_list",
        "we don't yet hide symbols by list; use -exported_symbols_list to say what to keep",
    ),
    (
        "weak_framework",
        "we don't yet record a framework as weakly referenced, and recording it strongly would \
         make a missing one fatal at startup",
    ),
    (
        "weak_library",
        "we don't yet record a library as weakly referenced",
    ),
    (
        "reexport_library",
        "we don't pass on what a dependency exports as though it were ours",
    ),
    ("sub_library", "we don't record sub-library relationships"),
    ("stack_size", "we don't set a non-default stack size"),
    ("image_base", "we don't set a non-default base address"),
    ("segprot", "we don't override segment protections"),
];

const IGNORED_FLAGS: &[&str] = &[];

impl MachOArgs {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            common: CommonArgs::from_env()?,
            ..Default::default()
        })
    }
}

#[expect(clippy::derivable_impls)]
impl Default for MachOArgs {
    fn default() -> Self {
        Self {
            common: CommonArgs::default(),
            platform_version: None,
            sysroot: None,
            lib_search_path: Vec::new(),
            plugin_path: None,
            dead_strip_dylibs: false,
            dead_strip: false,
            dylib: false,
            install_name: None,
            exported_symbols_list: None,
            rpaths: Vec::new(),
            framework_search_path: Vec::new(),
            current_version: None,
            compatibility_version: None,
            undefined: Vec::new(),
            exported_symbols: Vec::new(),
            all_load: false,
            strip_debug: false,
        }
    }
}

/// Where frameworks live when no `-F` says otherwise, in the order ld64 tries them.
const DEFAULT_FRAMEWORK_PATHS: &[&str] = &["/Library/Frameworks", "/System/Library/Frameworks"];

impl MachOArgs {
    /// The output path as bytes, for the places Mach-O records a path in the file itself.
    pub(crate) fn output_path_bytes(&self) -> &[u8] {
        self.common.output.as_os_str().as_encoded_bytes()
    }
}

impl platform::Args for MachOArgs {
    fn parse<S, I>(&mut self, input: I) -> Result
    where
        S: AsRef<str>,
        I: Iterator<Item = S>,
    {
        parse(self, input)
    }

    fn should_strip_debug(&self) -> bool {
        self.strip_debug
    }

    fn should_strip_all(&self) -> bool {
        false
    }

    fn entry_symbol_name<'a>(&'a self, _linker_script_entry: Option<&'a [u8]>) -> &'a [u8] {
        // TODO: probably add option
        b"_main"
    }

    fn lib_search_path(&self) -> &[Box<std::path::Path>] {
        &self.lib_search_path
    }

    fn framework_search_path(&self) -> &[Box<std::path::Path>] {
        &self.framework_search_path
    }

    fn force_undefined_symbol_names(&self) -> &[String] {
        &self.undefined
    }

    fn force_export_symbol_names(&self) -> &[String] {
        &self.exported_symbols
    }

    fn export_list_restricts_exports(&self) -> bool {
        true
    }

    fn common(&self) -> &crate::args::CommonArgs {
        &self.common
    }

    fn common_mut(&mut self) -> &mut crate::args::CommonArgs {
        &mut self.common
    }

    fn sysroot(&self) -> Option<&Path> {
        self.sysroot.as_deref()
    }

    fn should_export_all_dynamic_symbols(&self) -> bool {
        false
    }

    fn requires_fresh_output_file(&self) -> bool {
        // Everything we emit is code signed, so updating an existing output in place would leave
        // the kernel's cached signature for that vnode stale.
        true
    }

    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool {
        // Whether to pass on what a dependency exports as though it were ours. Mach-O spells that
        // `-reexport_library`, which we don't accept, so nothing is re-exported: what we export is
        // what we define.
        false
    }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        MACHO_PAGE_ALIGNMENT
    }

    fn should_merge_sections(&self) -> bool {
        // TODO
        true
    }

    fn export_list_path(&self) -> Option<&Path> {
        self.exported_symbols_list.as_deref()
    }

    fn should_gc_sections(&self) -> bool {
        // Only when asked. ld64 keeps everything unless given -dead_strip, and dropping something
        // that was actually reachable produces a binary that links and then misbehaves, so this is
        // not a default worth taking on.
        self.dead_strip
    }

    fn should_output_executable(&self) -> bool {
        !self.dylib
    }

    fn is_ignored_flag(&self, flag: &str) -> bool {
        IGNORED_FLAGS.contains(&flag)
    }
}

// Parse the supplied input arguments, which should not include the program name.
pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(
    args: &mut MachOArgs,
    mut input: I,
) -> Result {
    let mut modifier_stack = vec![Modifiers::default()];

    let arg_parser = setup_argument_parser();
    while let Some(arg) = input.next() {
        let arg = arg.as_ref();

        arg_parser.handle_argument(args, &mut modifier_stack, arg, &mut input)?;
    }

    if !args.common.unrecognized_options.is_empty() {
        let described = args
            .common
            .unrecognized_options
            .iter()
            .map(|option| {
                let name = option.trim_start_matches('-');
                match UNSUPPORTED_FLAGS.iter().find(|(flag, _)| *flag == name) {
                    Some((_, reason)) => format!("{option} is not supported: {reason}"),
                    None => format!("unrecognized option: {option}"),
                }
            })
            .join("\n");

        bail!("{described}");
    }

    // `-all_load` isn't positional the way `--whole-archive` is - it says every archive in the
    // link is to be taken whole, wherever it was named - so it's applied once everything has been
    // seen rather than to whatever followed it.
    if args.all_load {
        for input in &mut args.common.inputs {
            input.modifiers.whole_archive = true;
        }
    }

    Ok(())
}

// TODO: apparently the Mach-O system linker support neither long variants nor the prefixed
// variants.
fn setup_argument_parser() -> ArgumentParser<MachOArgs> {
    let mut parser = ArgumentParser::<MachOArgs>::new();

    parser
        .declare_with_param()
        .prefix("arch")
        .help("Set target architecture")
        .sub_option("arm64", "AArch64 Mach-O target", |_, _| Ok(()))
        .execute(|_, _modifier_stack, value| {
            bail!("-arch {value} is not yet supported");
        });
    parser
        .declare_with_three_params()
        .long("platform_version")
        .help("Set deployment target and the SDK version")
        .execute(
            |args, _modifier_stack, platform, minimum_version, sdk_version| {
                ensure!(
                    platform == "macos",
                    "'macos' expected for '-platform_version' argument"
                );
                args.platform_version = Some(PlatformVersion {
                    platform: platform.to_owned(),
                    minimum_version: SemanticVersion::try_from(minimum_version)
                        .context("cannot parse minimum_version")?,
                    sdk_version: SemanticVersion::try_from(sdk_version)
                        .context("cannot parse sdk_version")?,
                });
                Ok(())
            },
        );
    parser
        .declare_with_param()
        .long("syslibroot")
        .help("Set system root")
        .execute(|args, _modifier_stack, value| {
            args.common_mut().save_dir.handle_file(value);
            let sysroot = std::fs::canonicalize(value).unwrap_or_else(|_| PathBuf::from(value));
            // TODO: handle properly
            args.lib_search_path = vec![sysroot.join("usr/lib").into_boxed_path()];

            // The system framework directories move under the SDK along with the libraries. A `-F`
            // given earlier keeps its place at the front: those are the caller's own directories
            // and are searched before the system ones either way.
            args.framework_search_path.extend(
                DEFAULT_FRAMEWORK_PATHS
                    .iter()
                    .map(|path| sysroot.join(path.trim_start_matches('/')).into_boxed_path()),
            );

            args.sysroot = Some(Box::from(sysroot.as_path()));
            Ok(())
        });
    parser
        .declare_with_param()
        .long("lto_library")
        .help("Load plugin")
        .execute(|args, _modifier_stack, value| {
            args.plugin_path = Some(value.to_owned());
            Ok(())
        });
    parser
        .declare_with_param()
        .short("mllvm")
        .help("Pass an LLVM option")
        .execute(|args, _modifier_stack, value| match value {
            "-enable-linkonceodr-outlining" => Ok(()),
            _ => args.warn_unsupported(&format!("-mllvm {value}")),
        });
    parser
        .declare_with_param()
        .prefix("L")
        .help("Add directory to library search path")
        .execute(|args, _modifier_stack, value| {
            args.common_mut().save_dir.handle_file(value);
            args.lib_search_path.push(Box::from(Path::new(value)));
            Ok(())
        });
    parser
        .declare_with_param()
        .prefix("l")
        .help("Link with library")
        .sub_option_with_value(
            ":filename",
            "Link with specific file",
            |args, modifier_stack, value| {
                let stripped = value.strip_prefix(':').unwrap_or(value);
                let spec = InputSpec::File(Box::from(Path::new(stripped)));
                args.common_mut().inputs.push(Input {
                    spec,
                    search_first: None,
                    modifiers: *modifier_stack.last().unwrap(),
                });
                Ok(())
            },
        )
        .sub_option_with_value(
            "libname",
            "Link with library libname.dylib or libname.a",
            |args, modifier_stack, value| {
                let spec = InputSpec::Lib(Box::from(value));
                args.common_mut().inputs.push(Input {
                    spec,
                    search_first: None,
                    modifiers: *modifier_stack.last().unwrap(),
                });
                Ok(())
            },
        )
        .execute(|args, modifier_stack, value| {
            let spec = if let Some(stripped) = value.strip_prefix(':') {
                InputSpec::Search(Box::from(stripped))
            } else {
                InputSpec::Lib(Box::from(value))
            };
            args.common_mut().inputs.push(Input {
                spec,
                search_first: None,
                modifiers: *modifier_stack.last().unwrap(),
            });
            Ok(())
        });

    parser
        .declare()
        .long("dead_strip_dylibs")
        .execute(|args, _modifier_stack| {
            args.dead_strip_dylibs = true;
            Ok(())
        });

    parser
        .declare()
        .long("dylib")
        .help("Produce a dynamic library rather than an executable")
        .execute(|args, _modifier_stack| {
            args.dylib = true;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("exported_symbols_list")
        .help("Export only the symbols named in this file")
        .execute(|args, _modifier_stack, value| {
            args.exported_symbols_list = Some(Path::new(value).into());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("install_name")
        .long("dylib_install_name")
        .help("The path a dylib records for itself")
        .execute(|args, _modifier_stack, value| {
            args.install_name = Some(value.into());
            Ok(())
        });

    parser
        .declare()
        .long("dead_strip")
        .help("Remove code and data that nothing reaches")
        .execute(|args, _modifier_stack| {
            args.dead_strip = true;
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("F")
        .help("Add a directory to the framework search path")
        .execute(|args, _modifier_stack, value| {
            args.common_mut().save_dir.handle_file(value);
            args.framework_search_path.push(Box::from(Path::new(value)));
            Ok(())
        });

    parser
        .declare_with_param()
        .long("framework")
        .help("Link with a framework")
        .execute(|args, modifier_stack, value| {
            // ld64 accepts `-framework Foo,_debug` to pick a variant of the library inside the
            // bundle. Nothing we can link against ships one, so the suffix is not accepted rather
            // than silently ignored - quietly linking the wrong variant would be worse.
            ensure!(
                !value.contains(','),
                "Framework suffixes are not supported: `{value}`"
            );

            args.common_mut().inputs.push(Input {
                spec: InputSpec::Framework(Box::from(value)),
                search_first: None,
                modifiers: *modifier_stack.last().unwrap(),
            });
            Ok(())
        });

    parser
        .declare_with_param()
        .short("u")
        .help("Resolve this symbol as though something had referenced it")
        .execute(|args, _modifier_stack, value| {
            args.undefined.push(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("exported_symbol")
        .help("Export this symbol")
        .execute(|args, _modifier_stack, value| {
            args.exported_symbols.push(value.to_owned());
            Ok(())
        });

    parser
        .declare()
        .short("S")
        .help("Leave the debug map out of the output")
        .execute(|args, _modifier_stack| {
            args.strip_debug = true;
            Ok(())
        });

    parser
        .declare()
        .long("all_load")
        .help("Load every member of every archive, referenced or not")
        .execute(|args, _modifier_stack| {
            args.all_load = true;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("force_load")
        .help("Load every member of this archive, referenced or not")
        .execute(|args, modifier_stack, value| {
            args.common_mut().save_dir.handle_file(value);

            let mut modifiers = *modifier_stack.last().unwrap();
            modifiers.whole_archive = true;

            args.common_mut().inputs.push(Input {
                spec: InputSpec::File(Box::from(Path::new(value))),
                search_first: None,
                modifiers,
            });
            Ok(())
        });

    parser
        .declare_with_param()
        .long("current_version")
        .help("The version this dylib declares itself to be")
        .execute(|args, _modifier_stack, value| {
            args.current_version =
                Some(SemanticVersion::try_from(value).context("cannot parse -current_version")?);
            Ok(())
        });

    parser
        .declare_with_param()
        .long("compatibility_version")
        .help("The oldest version of this dylib an image built against it will accept")
        .execute(|args, _modifier_stack, value| {
            args.compatibility_version = Some(
                SemanticVersion::try_from(value).context("cannot parse -compatibility_version")?,
            );
            Ok(())
        });

    parser
        .declare_with_param()
        .long("rpath")
        .help("Add a directory for dyld to resolve @rpath dependencies against")
        .execute(|args, _modifier_stack, value| {
            // dyld tries the paths in the order they appear, so a repeat can't change the answer -
            // the earlier one already decided it. ld64 warns and emits one; we quietly emit one.
            if !args.rpaths.iter().any(|rpath| rpath.as_ref() == value) {
                args.rpaths.push(Box::from(value));
            }
            Ok(())
        });

    // The option declaration cannot be moved to declare_common_args as other platforms
    // use `prefix("o")`.
    parser
        .declare_with_param()
        .long("output")
        .short("o")
        .help("Set the output filename")
        .execute(|args, _modifier_stack, value| {
            args.common_mut().output = Arc::from(Path::new(value));
            Ok(())
        });

    super::declare_common_args(&mut parser);

    add_silently_ignored_flags(&mut parser);

    parser
}

fn add_silently_ignored_flags(parser: &mut ArgumentParser<MachOArgs>) {
    for flag in SILENTLY_IGNORED_FLAGS {
        let mut declaration = parser.declare();
        declaration = declaration.long(flag);
        declaration.execute(|_args, _modifier_stack| Ok(()));
    }

    for flag in SILENTLY_IGNORED_FLAGS_WITH_PARAM {
        let mut declaration = parser.declare_with_param();
        declaration = declaration.long(flag);
        declaration.execute(|_args, _modifier_stack, _value| Ok(()));
    }
}

#[cfg(test)]
mod tests {
    use super::MachOArgs;
    use super::PlatformVersion;
    use crate::args::InputSpec;
    use crate::args::macho::SemanticVersion;
    use crate::platform::Args as _;
    use object::macho::Version;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::Mutex;

    const INPUT1: &[&str] = &[
        "-arch",
        "arm64",
        "-lto_library",
        "/foo/bar/libLTO.dylib",
        "-no_deduplicate",
        "-platform_version",
        "macos",
        "14.0",
        "15.16.17",
        "-demangle",
        "-syslibroot",
        "/foo/bar",
        "-mllvm",
        "-enable-linkonceodr-outlining",
        "-o",
        "a.out",
        "-L/foo/lib",
        "-L",
        "/bar/lib",
        "main.o",
        "-lc++",
    ];

    fn input1_assertions(args: &MachOArgs) {
        assert_eq!(
            args.platform_version,
            Some(PlatformVersion {
                platform: "macos".to_owned(),
                minimum_version: SemanticVersion(Version::new(14, 0, 0)),
                sdk_version: SemanticVersion(Version::new(15, 16, 17)),
            })
        );
        assert!(args.common.demangle);
        assert_eq!(args.sysroot, Some(Box::from(Path::new("/foo/bar"))));
        assert!(args.common.inputs.iter().any(|i| match &i.spec {
            InputSpec::File(f) => f.as_ref() == Path::new("main.o"),
            InputSpec::Lib(_) | InputSpec::Search(_) | InputSpec::Framework(_) => false,
        }));
        assert!(args.common.inputs.iter().any(|i| match &i.spec {
            InputSpec::Lib(f) => f.as_ref() == "c++",
            InputSpec::File(_) | InputSpec::Search(_) | InputSpec::Framework(_) => false,
        }));
        assert!(
            args.lib_search_path
                .iter()
                .any(|p| p.as_ref() == Path::new("/foo/lib"))
        );
        assert!(
            args.lib_search_path
                .iter()
                .any(|p| p.as_ref() == Path::new("/bar/lib"))
        );
        assert_eq!(args.plugin_path, Some("/foo/bar/libLTO.dylib".to_owned()));
    }

    #[test]
    fn test_parse_inline_only_options() {
        let mut args = MachOArgs::new().unwrap();
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = warnings.clone();
        args.common.warning_callback = Box::new(move |warning| {
            warnings_clone
                .lock()
                .unwrap()
                .push(warning.warning().to_owned());
        });
        args.parse(INPUT1.iter()).unwrap();
        input1_assertions(&args);
        assert!(warnings.lock().unwrap().is_empty());
    }
}
