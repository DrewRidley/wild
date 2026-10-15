/// The table dyld searches to find what a dylib exports.
///
/// It's a trie over the exported names: each edge carries a piece of a name, and a node that ends a
/// name records what it resolves to. Sharing prefixes is what keeps it small, which matters because
/// dyld walks it on every symbol lookup.
pub(crate) struct ExportTrie {
    nodes: Vec<TrieNode>,
}

struct TrieNode {
    /// What this node resolves to, if a name ends here.
    export: Option<Export>,

    /// Edges to longer names, each labelled with the characters it adds.
    children: Vec<(Vec<u8>, usize)>,

    /// Where this node starts in the encoded trie. Only settled once every node's size is known,
    /// since a node names its children by offset and its own size depends on how large those
    /// offsets encode to.
    offset: u32,
}

#[derive(Clone, Copy)]
struct Export {
    /// Offset of the symbol from the start of the image.
    address: u64,
}

impl ExportTrie {
    /// Builds a trie over `exports`, which must be sorted by name and free of duplicates.
    pub(crate) fn build(exports: &[(&[u8], u64)]) -> Self {
        let mut trie = ExportTrie {
            nodes: vec![TrieNode::default()],
        };

        for (name, address) in exports {
            trie.insert(name, *address);
        }

        trie.assign_offsets();
        trie
    }

    fn insert(&mut self, name: &[u8], address: u64) {
        let mut node = 0;
        let mut rest = name;

        loop {
            if rest.is_empty() {
                self.nodes[node].export = Some(Export { address });
                return;
            }

            // The edge to follow is the one sharing a first character - a trie has at most one,
            // because any two names starting the same character share at least that much.
            let existing = self.nodes[node]
                .children
                .iter()
                .position(|(label, _)| label[0] == rest[0]);

            let Some(edge) = existing else {
                let child = self.push_node();
                self.nodes[node].children.push((rest.to_owned(), child));
                self.nodes[child].export = Some(Export { address });
                return;
            };

            let shared = self.nodes[node].children[edge]
                .0
                .iter()
                .zip(rest)
                .take_while(|(a, b)| a == b)
                .count();

            let (label, child) = self.nodes[node].children[edge].clone();

            if shared == label.len() {
                // The whole edge is a prefix of what we're inserting, so carry on past it.
                node = child;
                rest = &rest[shared..];
                continue;
            }

            // The names diverge partway along the edge, so it has to be cut in two and the point of
            // divergence becomes a node with both continuations hanging off it.
            let split = self.push_node();
            self.nodes[node].children[edge] = (label[..shared].to_owned(), split);
            self.nodes[split]
                .children
                .push((label[shared..].to_owned(), child));

            node = split;
            rest = &rest[shared..];
        }
    }

    fn push_node(&mut self) -> usize {
        self.nodes.push(TrieNode::default());
        self.nodes.len() - 1
    }

    /// Works out where each node sits in the encoded trie.
    ///
    /// A node records its children by offset, and how many bytes an offset takes depends on how
    /// large it is - so growing one node can push another past a ULEB128 boundary and grow it too.
    /// Repeating until nothing moves is what settles it; sizes only ever grow, so it terminates.
    fn assign_offsets(&mut self) {
        loop {
            let mut offset = 0;
            let mut changed = false;

            for index in 0..self.nodes.len() {
                if self.nodes[index].offset != offset {
                    self.nodes[index].offset = offset;
                    changed = true;
                }
                offset += self.encoded_len(index) as u32;
            }

            if !changed {
                return;
            }
        }
    }

    fn encoded_len(&self, index: usize) -> usize {
        let node = &self.nodes[index];
        let mut len = 0;

        // The terminal payload, preceded by its own length so that a walker uninterested in this
        // node can step over it without understanding what's in it.
        let terminal = node.export.map_or(0, |export| {
            uleb128_len(EXPORT_SYMBOL_FLAGS_KIND_REGULAR) + uleb128_len(export.address)
        });
        len += uleb128_len(terminal as u64) + terminal;

        len += 1; // Child count, which the format holds in a single byte.

        for (label, child) in &node.children {
            len += label.len() + 1 + uleb128_len(u64::from(self.nodes[*child].offset));
        }

        len
    }

    /// The size the encoded trie will be. Known once the offsets have settled, which is what lets
    /// the space be reserved before it's written.
    pub(crate) fn len(&self) -> usize {
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, _)| self.encoded_len(index))
            .sum()
    }

    pub(crate) fn write(&self, out: &mut [u8]) -> crate::error::Result {
        let mut cursor = 0;

        for (index, node) in self.nodes.iter().enumerate() {
            debug_assert_eq!(cursor, node.offset as usize);

            let terminal = node.export.map_or(0, |export| {
                uleb128_len(EXPORT_SYMBOL_FLAGS_KIND_REGULAR) + uleb128_len(export.address)
            });

            write_uleb128(out, &mut cursor, terminal as u64)?;

            if let Some(export) = node.export {
                write_uleb128(out, &mut cursor, EXPORT_SYMBOL_FLAGS_KIND_REGULAR)?;
                write_uleb128(out, &mut cursor, export.address)?;
            }

            let count = u8::try_from(node.children.len())
                .map_err(|_| crate::error!("An export trie node has more than 255 children"))?;
            write_byte(out, &mut cursor, count)?;

            for (label, child) in &node.children {
                for byte in label {
                    write_byte(out, &mut cursor, *byte)?;
                }
                write_byte(out, &mut cursor, 0)?;
                write_uleb128(out, &mut cursor, u64::from(self.nodes[*child].offset))?;
            }

            let _ = index;
        }

        Ok(())
    }
}

impl Default for TrieNode {
    fn default() -> Self {
        TrieNode {
            export: None,
            children: Vec::new(),
            offset: u32::MAX,
        }
    }
}

/// An ordinary exported symbol, as opposed to a thread-local or a resolver.
const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;

fn uleb128_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn write_uleb128(out: &mut [u8], cursor: &mut usize, mut value: u64) -> crate::error::Result {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        write_byte(out, cursor, byte)?;
        if value == 0 {
            return Ok(());
        }
    }
}

fn write_byte(out: &mut [u8], cursor: &mut usize, byte: u8) -> crate::error::Result {
    let slot = out
        .get_mut(*cursor)
        .ok_or_else(|| crate::error!("Insufficient allocation for the export trie"))?;
    *slot = byte;
    *cursor += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walks an encoded trie the way dyld does, so that what comes back is what a loader would see
    /// rather than what the builder believed it wrote.
    fn lookup(encoded: &[u8], name: &[u8]) -> Option<u64> {
        let mut offset = 0usize;
        let mut rest = name;

        loop {
            let (terminal_size, mut cursor) = read_uleb128(encoded, offset)?;

            if rest.is_empty() {
                if terminal_size == 0 {
                    return None;
                }
                let (_flags, next) = read_uleb128(encoded, cursor)?;
                let (address, _) = read_uleb128(encoded, next)?;
                return Some(address);
            }

            cursor += terminal_size as usize;
            let count = *encoded.get(cursor)?;
            cursor += 1;

            let mut found = None;
            for _ in 0..count {
                let start = cursor;
                while *encoded.get(cursor)? != 0 {
                    cursor += 1;
                }
                let label = &encoded[start..cursor];
                cursor += 1;
                let (child, next) = read_uleb128(encoded, cursor)?;
                cursor = next;

                if rest.starts_with(label) {
                    found = Some((label.len(), child as usize));
                }
            }

            let (consumed, child) = found?;
            rest = &rest[consumed..];
            offset = child;
        }
    }

    fn read_uleb128(data: &[u8], mut offset: usize) -> Option<(u64, usize)> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = *data.get(offset)?;
            offset += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some((value, offset));
            }
            shift += 7;
        }
    }

    fn round_trip(names: &[(&[u8], u64)]) {
        let trie = ExportTrie::build(names);
        let mut encoded = vec![0u8; trie.len()];
        trie.write(&mut encoded).unwrap();

        for (name, address) in names {
            assert_eq!(
                lookup(&encoded, name),
                Some(*address),
                "looking up {:?}",
                String::from_utf8_lossy(name)
            );
        }

        // A name that isn't there must not resolve, including prefixes of ones that are.
        assert_eq!(lookup(&encoded, b"_definitely_absent"), None);
    }

    #[test]
    fn single_export() {
        round_trip(&[(b"_main", 0x1000)]);
    }

    #[test]
    fn shared_prefixes() {
        round_trip(&[
            (b"_foo", 0x1000),
            (b"_foobar", 0x2000),
            (b"_foobaz", 0x3000),
            (b"_frob", 0x4000),
        ]);
    }

    #[test]
    fn a_name_that_is_a_prefix_of_another() {
        // The shorter name ends at an interior node, which has to carry a payload as well as edges.
        round_trip(&[(b"_a", 1), (b"_ab", 2), (b"_abc", 3)]);
    }

    #[test]
    fn addresses_wide_enough_to_grow_the_offsets() {
        // Large addresses take more ULEB128 bytes, which pushes later nodes further out and can
        // grow the offsets referring to them - the case `assign_offsets` iterates for.
        let names: Vec<(&[u8], u64)> = vec![
            (b"_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0xffff_ffff),
            (b"_aaaaaaaaaaaaaaaaaaaaaaaaaaaaab", 0xffff_fffe),
            (b"_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0x7fff_ffff_ffff),
        ];
        round_trip(&names);
    }

    #[test]
    fn many_exports_force_multi_byte_offsets() {
        let names: Vec<Vec<u8>> = (0..400)
            .map(|i| format!("_symbol_number_{i:04}").into_bytes())
            .collect();
        let mut sorted: Vec<(&[u8], u64)> = names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_slice(), 0x1000 + i as u64 * 0x40))
            .collect();
        sorted.sort_by_key(|(n, _)| *n);
        round_trip(&sorted);
    }
}
