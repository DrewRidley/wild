//! Independent reader for `LC_DYLD_CHAINED_FIXUPS`, written from the Mach-O / dyld chained
//! fixups format description. This is an oracle for libwild's Mach-O writer, so it must not
//! import, call or copy anything from `libwild::macho*`.

use crate::Binary;
use crate::Report;

pub(crate) fn report_diffs(_report: &mut Report, _objects: &[Binary]) {
    // TODO(C1): implement.
}
