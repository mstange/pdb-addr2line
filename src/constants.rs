// Constants copied from the pdb crate
// see https://github.com/willglynn/pdb/issues/120

pub const S_PUB32: u16 = 0x110e; // a public symbol (CV internal reserved)
pub const S_PUB32_ST: u16 = 0x1009; // a public symbol (CV internal reserved)
pub const S_LPROC32_ST: u16 = 0x100a; // Local procedure start
pub const S_GPROC32_ST: u16 = 0x100b; // Global procedure start
pub const S_LPROC32: u16 = 0x110f; // Local procedure start
pub const S_GPROC32: u16 = 0x1110; // Global procedure start
pub const S_LPROC32_ID: u16 = 0x1146;
pub const S_GPROC32_ID: u16 = 0x1147;
pub const S_LPROC32_DPC: u16 = 0x1155; // DPC local procedure start
pub const S_LPROC32_DPC_ID: u16 = 0x1156;
pub const S_THUNK32_ST: u16 = 0x0206; // Thunk Start
pub const S_THUNK32: u16 = 0x1102; // Thunk Start
pub const S_SEPCODE: u16 = 0x1132;
pub const S_INLINESITE: u16 = 0x114d; // inlined function callsite.
pub const S_INLINESITE2: u16 = 0x115d; // extended inline site information
