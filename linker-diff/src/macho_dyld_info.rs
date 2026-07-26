//! Differential check of Apple's `dyld_info` output between our binary and the reference
//! linker's. Independent of both libwild and of the in-tree chained-fixups parser.

use crate::Binary;
use crate::Report;

pub(crate) fn report_diffs(_report: &mut Report, _objects: &[Binary]) {
    // TODO(C2): implement.
}
