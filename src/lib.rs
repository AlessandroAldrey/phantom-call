#[cfg(not(any(all(target_os = "windows", target_arch = "x86_64"), test)))]
compile_error!("phantom-call requires Windows x86-64");

pub mod gadget;
pub mod invoke;
pub mod ssn;

pub use ssn::NtdllBounds;

/// # Example
/// ```ignore
/// let bounds = NtdllBounds { start: text_start, end: text_end };
/// let info   = unsafe { ssn::resolve(nt_alloc_fn, &bounds) }.unwrap();
/// let status = unsafe { syscall!(info, base, zero, size, alloc_type, protect) };
/// ```
#[repr(C)]
pub struct SyscallInfo {
    pub ssn: u16,
    pub gadget: *const u8,
}

// Safety: SyscallInfo is populated once at resolution time and never mutated.
unsafe impl Send for SyscallInfo {}
unsafe impl Sync for SyscallInfo {}
