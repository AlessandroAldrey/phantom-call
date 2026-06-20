/// # Safety
/// Core indirect syscall stub — naked, no prologue/epilogue emitted by rustc.
///
/// # Argument layout on entry (Windows x64 ABI)
///
/// ```text
/// rcx          = ssn
/// rdx          = gadget   (*const u8 into ntdll .text)
/// r8           = a1       → NT arg3  (left in place)
/// r9           = a2       → NT arg4  (left in place)
/// [rsp + 0x28] = a3       → NT arg1  (loaded into r10)
/// [rsp + 0x30] = a4       → NT arg2  (loaded into rdx)
/// [rsp + 0x38] = a5       → NT arg5  (kernel reads directly)
/// [rsp + 0x40] = a6       → NT arg6  (kernel reads directly)
/// ```
///
/// # NT kernel convention produced
///
/// ```text
/// eax = ssn   r10 = arg1   rdx = arg2   r8 = arg3   r9 = arg4
/// [rsp + 0x38] = arg5      [rsp + 0x40] = arg6
/// ```
///
/// # Phase ordering (no stack writes, no dependency hazards)
///
/// ```text
/// Phase 1  mov r11, rdx           stash gadget before rdx is overwritten
/// Phase 1  mov eax, ecx           SSN → eax
/// Phase 2  mov r10, [rsp + 0x28]  a3 → r10 (NT arg1)
/// Phase 2  mov rdx, [rsp + 0x30]  a4 → rdx (NT arg2)
/// Phase 3  r8 / r9 unchanged      NT arg3/4 already in position
/// Phase 4  stack unchanged        kernel reads NT arg5/6 from [rsp+0x38/0x40]
///          jmp r11                indirect branch into ntdll gadget
/// ```
#[unsafe(naked)]
pub unsafe extern "system" fn do_syscall(
    ssn: u32,
    gadget: *const u8,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> usize {
    core::arch::naked_asm!(
        "mov r11, rdx",          // Phase 1 — save gadget
        "mov eax, ecx",          // Phase 1 — SSN into eax
        "mov r10, [rsp + 0x28]", // Phase 2 — a3 → r10 (NT arg1)
        "mov rdx, [rsp + 0x30]", // Phase 2 — a4 → rdx (NT arg2)
        "jmp r11",               // jump; gadget contains `syscall; ret`
    )
}

/// Invokes an indirect syscall using a pre-resolved [`crate::SyscallInfo`].
///
/// Accepts 0–6 NT arguments in natural order. The macro reorders them before
/// dispatching to [`do_syscall`] so that register and stack positions match
/// the NT kernel's expectations exactly:
///
/// ```text
/// syscall!(info, arg1, arg2, arg3, arg4, arg5, arg6)
///               ↓ macro reorders ↓
/// do_syscall(ssn, gadget,  arg3, arg4,  arg1, arg2,  arg5, arg6)
///                          ↑r8   ↑r9   ↑+0x28 ↑+0x30 ↑+0x38 ↑+0x40
/// ```
///
/// All arguments are widened to `usize`; cast pointer types with `as usize`
/// at the call site. Returns the raw `NTSTATUS` as `usize`.
///
/// # Safety
/// Arguments must be valid for the target NT function. Mismatched counts or
/// types produce undefined behavior.
#[macro_export]
macro_rules! syscall {
    ($info:expr) => {
        $crate::invoke::do_syscall($info.ssn as u32, $info.gadget, 0, 0, 0, 0, 0, 0)
    };
    ($info:expr, $arg1:expr) => {
        $crate::invoke::do_syscall(
            $info.ssn as u32,
            $info.gadget,
            0,
            0,
            $arg1 as usize,
            0,
            0,
            0,
        )
    };
    ($info:expr, $arg1:expr, $arg2:expr) => {
        $crate::invoke::do_syscall(
            $info.ssn as u32,
            $info.gadget,
            0,
            0,
            $arg1 as usize,
            $arg2 as usize,
            0,
            0,
        )
    };
    ($info:expr, $arg1:expr, $arg2:expr, $arg3:expr) => {
        $crate::invoke::do_syscall(
            $info.ssn as u32,
            $info.gadget,
            $arg3 as usize,
            0,
            $arg1 as usize,
            $arg2 as usize,
            0,
            0,
        )
    };
    ($info:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr) => {
        $crate::invoke::do_syscall(
            $info.ssn as u32,
            $info.gadget,
            $arg3 as usize,
            $arg4 as usize,
            $arg1 as usize,
            $arg2 as usize,
            0,
            0,
        )
    };
    ($info:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr) => {
        $crate::invoke::do_syscall(
            $info.ssn as u32,
            $info.gadget,
            $arg3 as usize,
            $arg4 as usize,
            $arg1 as usize,
            $arg2 as usize,
            $arg5 as usize,
            0,
        )
    };
    ($info:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr, $arg6:expr) => {
        $crate::invoke::do_syscall(
            $info.ssn as u32,
            $info.gadget,
            $arg3 as usize,
            $arg4 as usize,
            $arg1 as usize,
            $arg2 as usize,
            $arg5 as usize,
            $arg6 as usize,
        )
    };
}
