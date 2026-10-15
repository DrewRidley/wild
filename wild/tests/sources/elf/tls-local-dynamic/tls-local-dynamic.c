//#AbstractConfig:default
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata
//#DiffIgnore:dynsym.foo.section

//#Config:gcc:default
//#SkipArch: ppc64le
//#CompArgs:-ftls-model=local-dynamic -fPIC -O2
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-z,now

//#Config:gcc-no-relax:gcc
//#LinkArgs:-Wl,-z,now,--no-relax
//#DiffEnabled:false
// TODO: For some reason, the test fails under QEMU for LoongArch64, even though it runs correctly
// on a native Alpine Linux system.
//#SkipArch:loongarch64,ppc64le

//#Config:gcc-no-relax-aarch64:gcc-no-relax
//#CompArgs:-ftls-model=local-dynamic -fPIC -O2 -mtls-dialect=trad
//#Arch:aarch64

//#Config:malfunction-no-movzx0lsl16:gcc
//#Arch:aarch64
//#Malfunction:no-movzx0lsl16
//#MalfunctionExpectKey:rel.R_AARCH64_NONE.R_AARCH64_TLSLE_MOVW_TPREL_G1

_Thread_local long foo = 42;

int main() { return foo; }
