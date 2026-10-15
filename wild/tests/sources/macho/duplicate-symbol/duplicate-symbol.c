//#Object:other-definition.c
//#ExpectError:[Dd]uplicate symbol.*_clashing

// Defining the same symbol in two objects has to be reported rather than silently picking one.
// Reaching the diagnostic asks the section header whether it belongs to a section group, which is
// an ELF concept that Mach-O has no equivalent of - answering that used to panic.
int clashing(void) { return 1; }

int main(void) { return clashing(); }
