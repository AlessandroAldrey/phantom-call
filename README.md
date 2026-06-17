# Phantom Call

Phantom Call is a Rust library designed for executing indirect syscalls on Windows x86-64. It dynamically resolves System Service Numbers (SSNs) and locates execution gadgets within `ntdll.dll` to bypass user-mode hooks and interact with the NT kernel.

## Features

* **Dynamic SSN Resolution**: Implements advanced heuristic scanning (adapted from Tartarus Gate principles) to dynamically resolve SSNs. It correctly identifies syscall numbers even when the NT prologue is modified by user-mode hooks or EDR instrumentation.
* **Indirect Syscalls**: Bypasses inline hooks by finding and executing raw `syscall; ret` gadgets directly from the `ntdll.dll` memory space.
* **CET Mitigation Awareness**: Searches for gadgets within a specific radius to ensure compatibility with modern Windows 11 mitigations like Control-flow Enforcement Technology (CET).
* **Zero-Overhead Invocation**: Uses an `unsafe(naked)` assembly block for phase-ordered register and stack preparation, ensuring precise adherence to the Windows x64 ABI without compiler-injected prologue/epilogue interference.
* **Ergonomic API**: Exposes a convenient `syscall!` macro for dispatching syscalls with up to 6 arguments cleanly.

## Usage

Phantom Call requires a base pointer to an NT function and the readable bounds of the `ntdll.dll` `.text` section. These bounds must be populated externally (e.g., via a PEB/LDR walker).

### Example

```rust
use phantom_call::{NtdllBounds, ssn, syscall};

// 1. Obtain the bounds of ntdll.dll's .text section
// start = DllBase + VirtualAddress, end = start + SizeOfRawData
let bounds = NtdllBounds { start: text_start, end: text_end };

// 2. Resolve the SSN and syscall gadget for a specific NT function
let info = unsafe { ssn::resolve(nt_alloc_fn_ptr, &bounds) }.expect("Failed to resolve SSN");

// 3. Execute the indirect syscall
let status = unsafe { syscall!(info, process_handle, base_address, zero_bits, region_size, alloc_type, protect) };
```

## Internal Mechanics

1. **Resolution (`ssn::resolve`)**: 
   - Examines the stub of the provided function pointer.
   - If clean (unhooked), it directly extracts the SSN.
   - If hooked, it scans adjacent stubs bidirectionally (`scan_up` and `scan_down`) to cross-validate and calculate the true SSN via proximity.
2. **Gadget Location**: 
   - Scans a 24-byte radius around the stub to discover a `syscall; ret` (`0x0F05`) gadget natively present in the library, avoiding user-allocated executable memory.
3. **Execution (`invoke::do_syscall`)**:
   - Reorders provided arguments to match NT Kernel stack and register expectations exactly.
   - Executes an indirect branch (`jmp`) into the identified `ntdll.dll` gadget.

## Disclaimer

This library is intended for systems programming, educational use, and authorized security research.
