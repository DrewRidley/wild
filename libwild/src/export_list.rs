use crate::error;
use crate::error::Result;
use crate::hash::PreHashed;
use crate::input_data::ScriptData;
use crate::linker_script::skip_comments_and_whitespace;
use crate::symbol::UnversionedSymbolName;
use crate::version_script::MatchRules;
use crate::version_script::SymbolLookupNameWrapper;
use crate::version_script::parse_matcher;
use winnow::BStr;
use winnow::Parser;

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

#[derive(Debug, Default)]
pub(crate) struct ExportList<'data>(MatchRules<'data>);

impl<'data> ExportList<'data> {
    /// Reads the plain form: one symbol name per line, `#` starting a comment.
    ///
    /// This is what `-exported_symbols_list` takes. It is not the same file as ELF's version
    /// script, which the parse below reads - that one groups its names in braces and can say what
    /// is *not* exported as well as what is.
    pub(crate) fn parse_lines(data: ScriptData<'data>) -> Result<Self> {
        let mut out = ExportList::default();

        for line in data.raw.split(|byte| *byte == b'\n') {
            let line = match line.iter().position(|byte| *byte == b'#') {
                Some(comment) => &line[..comment],
                None => line,
            };

            let name = trim_ascii_whitespace(line);
            if name.is_empty() {
                continue;
            }

            // A name may be a glob, which `parse_matcher` already knows how to classify - going
            // through it keeps globbing behaving the same however the list was written.
            out.0
                .push(crate::version_script::ParsedSymbolMatcher::Single(
                    crate::version_script::classify_matcher(name)?,
                ));
        }

        Ok(out)
    }

    pub(crate) fn parse(data: ScriptData<'data>) -> Result<Self> {
        parse_export_list
            .parse(BStr::new(data.raw))
            .map_err(|err| error!("Failed to parse symbol export list:\n{err}"))
    }

    // Based on Version Script counterpart
    pub(crate) fn contains(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        let mut lookup_name = SymbolLookupNameWrapper::from_name(name);

        if self.0.general.matches_exact(&mut lookup_name, false)
            || self.0.cxx.matches_exact(&mut lookup_name, true)
        {
            return true;
        }

        for &non_star in &[true, false] {
            if self
                .0
                .general
                .matches_glob(&mut lookup_name, non_star, false)
                || self.0.cxx.matches_glob(&mut lookup_name, non_star, true)
            {
                return true;
            }
        }

        if self.0.general.matches_all() || self.0.cxx.matches_all() {
            return true;
        }

        false
    }

    pub(crate) fn add_symbol(&mut self, symbol: &'data str, without_semicolon: bool) -> Result<()> {
        let matcher = parse_matcher(&mut BStr::new(symbol), without_semicolon)?;
        self.0.push(matcher);
        Ok(())
    }
}

fn parse_export_list<'input>(input: &mut &'input BStr) -> winnow::Result<ExportList<'input>> {
    let mut out = ExportList::default();

    skip_comments_and_whitespace(input)?;

    '{'.parse_next(input)?;

    loop {
        skip_comments_and_whitespace(input)?;

        if input.starts_with(b"};") {
            "};".parse_next(input)?;
            skip_comments_and_whitespace(input)?;
            break;
        }

        let matcher = parse_matcher(input, false)?;
        out.0.push(matcher);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input_data::ScriptData;

    #[test]
    fn parse_inline() {
        let data = ScriptData {
            raw: b"{ f*; \"bar\"; extern \"C++\" { baz; qux; }; };",
        };
        let export_list = ExportList::parse(data).unwrap();
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"foo")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"bar")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"baz")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"qux")));
        assert!(!export_list.contains(&UnversionedSymbolName::prehashed(b"not_exported")));
    }

    #[test]
    fn parse_multiline_with_comments() {
        let data = ScriptData {
            raw: b"{
                    # Single line comment
                    foo;
                    \"bar\"; # With a quote

                    /*
                    * And a C-style comment
                    */
                    baz*;

                    extern \"C++\" {
                        qux; # C++ symbol
                    };
                };",
        };
        let export_list = ExportList::parse(data).unwrap();
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"foo")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"bar")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"baz-test")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"qux")));
        assert!(!export_list.contains(&UnversionedSymbolName::prehashed(b"not_exported")));
    }

    #[test]
    fn externs() {
        let data = ScriptData {
            raw: b"{
                    extern \"C\" {
                        foo;
                    };
                    extern \"C++\" {
                        bar;
                    };
                };",
        };
        let export_list = ExportList::parse(data).unwrap();
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"foo")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"bar")));
        assert!(!export_list.contains(&UnversionedSymbolName::prehashed(b"not_exported")));
    }
}
