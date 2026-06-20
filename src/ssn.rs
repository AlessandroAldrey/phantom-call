use core::ffi::c_void;

use crate::{SyscallInfo, gadget};

const PROLOGUE: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
const MAX_STUBS: usize = 5;

// Readable bounds of ntdll's .text section.
// Populate from your PEB/LDR walker:
//   `start` = DllBase + .text VirtualAddress
//   `end`   = start   + .text SizeOfRawData
pub struct NtdllBounds {
    pub start: *const u8,
    pub end: *const u8,
}

unsafe impl Send for NtdllBounds {}
unsafe impl Sync for NtdllBounds {}

#[inline]
fn in_bounds(ptr: *const u8, bounds: &NtdllBounds) -> bool {
    ptr >= bounds.start && ptr.wrapping_add(11) <= bounds.end
}

// Caller must verify `in_bounds(ptr, bounds)` before calling.
#[inline]
unsafe fn read_stub(ptr: *const u8) -> [u8; 11] {
    let mut buf = [0u8; 11];
    unsafe {
        core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 11);
    }
    buf
}

/// Returns `true` if `b` matches an unhooked native NT stub based on adapted Tartarus Gate principles.
///
/// Instead of strictly validating fixed trailing syscall/ret bytes—which frequently shift
/// due to modern Windows 11 mitigations (e.g., CET, telemetry instrumentation), this routine
/// checks the integrity of the leading edge and prevents inline hooking attempts.
///
/// ```text
/// 4C 8B D1        mov r10, rcx     <- Verified via PROLOGUE bounds
/// B8 XX XX 00 00  mov eax, <SSN>   <- Verified to ensure no JMP (0xE9) replaces the SSN
/// ... [Variable padding / Mitigations] -> Trailing bytes are handled dynamically elsewhere
/// ```
///
/// Catches both classic hooks (replacing the prologue at offset 0) and intermediate
/// Tartarus Gate hooks (replacing the `B8` opcode or the SSN intermediate bytes with a JMP).
#[inline]
fn is_clean(b: &[u8; 11]) -> bool {
    let has_prologue = b[0..4] == PROLOGUE;
    let no_tartarus_hook = b[4] != 0xE9 && b[5] != 0xE9;

    has_prologue && no_tartarus_hook
}

#[inline]
unsafe fn find_syscall_gadget_nearby(
    stub_ptr: *const u8,
    bounds: &NtdllBounds,
) -> Option<*const u8> {
    // Scan a 24-byte radius to account for CET mitigations or stub misalignment.
    for offset in 4..24 {
        let test_ptr = unsafe { stub_ptr.add(offset) };
        if test_ptr.wrapping_add(2) > bounds.end {
            break;
        }
        let opcode = unsafe { core::ptr::read_unaligned(test_ptr as *const u16) };
        if opcode == 0x050F {
            // 0x0F, 0x05 Little Endian
            return Some(test_ptr);
        }
    }
    None
}

unsafe fn scan_up(base: *const u8, bounds: &NtdllBounds) -> Option<(u16, *const u8)> {
    let mut ptr = unsafe { base.add(1) };
    let mut n: usize = 0;

    while in_bounds(ptr, bounds) {
        let b = unsafe { read_stub(ptr) };

        if b[0..4] == PROLOGUE {
            n += 1;
            if n > MAX_STUBS {
                return None;
            }
            if is_clean(&b) {
                let clean_ssn = u16::from_le_bytes([b[4], b[5]]);
                let ssn = clean_ssn.checked_sub(n as u16)?;
                if let Some(gadget_ptr) = unsafe { find_syscall_gadget_nearby(ptr, bounds) } {
                    return Some((ssn, gadget_ptr));
                }
            }
            ptr = unsafe { ptr.add(4) };
        } else {
            ptr = unsafe { ptr.add(1) };
        }
    }

    None
}

unsafe fn scan_down(base: *const u8, bounds: &NtdllBounds) -> Option<(u16, *const u8)> {
    if base <= bounds.start {
        return None;
    }

    let mut ptr = unsafe { base.sub(1) };
    let mut n: usize = 0;

    loop {
        if !in_bounds(ptr, bounds) {
            break;
        }

        let b = unsafe { read_stub(ptr) };

        if b[0..4] == PROLOGUE {
            n += 1;
            if n > MAX_STUBS {
                return None;
            }
            if is_clean(&b) {
                let clean_ssn = u16::from_le_bytes([b[4], b[5]]);
                let ssn = clean_ssn.checked_add(n as u16)?;
                if let Some(gadget_ptr) = unsafe { find_syscall_gadget_nearby(ptr, bounds) } {
                    return Some((ssn, gadget_ptr));
                }
            }
        }

        if ptr == bounds.start {
            break;
        }
        ptr = unsafe { ptr.sub(1) };
    }

    None
}

/// Resolves the System Call Number (SSN) by parsing the function's assembly instructions.
///
/// # Safety
///
/// This function is unsafe because it performs raw pointer dereferencing and reads
/// arbitrary memory addresses starting at `fn_addr` to parse bytecode signatures.
/// The caller must ensure `fn_addr` points to a valid exported function inside NTDLL.
pub unsafe fn resolve(fn_addr: *const c_void, bounds: &NtdllBounds) -> Option<SyscallInfo> {
    let base = fn_addr as *const u8;

    if in_bounds(base, bounds) {
        let b = unsafe { read_stub(base) };
        if is_clean(&b) {
            let ssn = u16::from_le_bytes([b[4], b[5]]);
            if let Some(gadget_ptr) = unsafe { find_syscall_gadget_nearby(base, bounds) } {
                gadget::cache(gadget_ptr);
                return Some(SyscallInfo {
                    ssn,
                    gadget: gadget_ptr,
                });
            }
        }
    }

    let up = unsafe { scan_up(base, bounds) };
    let down = unsafe { scan_down(base, bounds) };

    match (up, down) {
        (Some((ssn_u, g_u)), Some((ssn_d, _))) => {
            if ssn_u == ssn_d {
                gadget::cache(g_u);
                Some(SyscallInfo {
                    ssn: ssn_u,
                    gadget: g_u,
                })
            } else {
                None
            }
        }
        (Some((ssn, g)), None) => {
            gadget::cache(g);
            Some(SyscallInfo { ssn, gadget: g })
        }
        (None, Some((ssn, g))) => {
            gadget::cache(g);
            Some(SyscallInfo { ssn, gadget: g })
        }
        (None, None) => None,
    }
}
