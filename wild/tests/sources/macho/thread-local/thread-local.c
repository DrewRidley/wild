// Linked through the compiler driver so that libSystem, which provides __tlv_bootstrap, is on the
// link line - otherwise the link fails earlier on that undefined symbol instead.
//#LinkerDriver:clang
// ld64 and lld both link this fine, so there's nothing to compare against until wild can too.
//#ReferenceLinkers:
//#ExpectErrorWild:thread-local variables are not supported

// The addressing side of TLS works - the sections are laid out and the TLVP relocation pair
// relaxes the same way ld64 does - but the tlv_descriptor contents don't get built, so wild
// refuses the link rather than emitting a binary that takes SIGBUS on first use. When the
// descriptors are implemented, this should become a test that runs and returns 42.
_Thread_local int counter = 41;

int main(void) {
  counter++;
  return counter;
}
