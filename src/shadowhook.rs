//! Minimal FFI bindings for ByteDance's android-inline-hook (shadowhook).
//!
//! Upstream: <https://github.com/bytedance/android-inline-hook>
//!
//! We only bind the three entry points we actually need. shadowhook itself
//! is linked as a static archive (`libshadowhook.a`) built for
//! `aarch64-linux-android`; see `build.rs`.

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicBool, Ordering};

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
#[allow(dead_code)]
#[repr(C)]
pub enum ShadowhookMode {
    /// Multiple coexisting hooks per symbol (LIFO chain). shadowhook's
    /// default. Values must match `shadowhook_mode_t` in `shadowhook.h`.
    Shared = 0,
    /// One hook per target symbol. Re-hooking returns the same stub.
    Unique = 1,
}

unsafe extern "C" {
    /// Initialize shadowhook. Safe to call more than once; subsequent calls
    /// after the first are no-ops and return 0.
    fn shadowhook_init(mode: c_int, debuggable: bool) -> c_int;

    /// Install an inline hook on `sym_name` as exported by `lib_name`
    /// (e.g. `"libc.so"`). On success returns an opaque non-null stub and
    /// writes the trampoline-to-original into `*orig_addr`. Returns null on
    /// failure; call `shadowhook_get_errno()` for details (not bound here).
    fn shadowhook_hook_sym_name(
        lib_name: *const c_char,
        sym_name: *const c_char,
        new_addr: *mut c_void,
        orig_addr: *mut *mut c_void,
    ) -> *mut c_void;

    #[allow(dead_code)]
    fn shadowhook_unhook(stub: *mut c_void) -> c_int;
}

static INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Initialize shadowhook exactly once per process. Returns Ok on success
/// or if already initialized; Err with the raw return code otherwise.
pub fn init_once() -> Result<(), c_int> {
    if INIT_DONE.load(Ordering::Acquire) {
        return Ok(());
    }
    // SAFETY: FFI call with no arguments that reference Rust memory.
    let rc = unsafe { shadowhook_init(ShadowhookMode::Unique as c_int, false) };
    if rc == 0 {
        INIT_DONE.store(true, Ordering::Release);
        Ok(())
    } else {
        Err(rc)
    }
}

/// Install an inline hook on `lib!sym`. `new_fn` is the replacement
/// function; on success the original-trampoline pointer is written to
/// `*out_orig`. Returns the shadowhook stub (opaque) or null on failure.
///
/// # Safety
///
/// `new_fn` must be a valid function pointer with a signature ABI-compatible
/// with the real target symbol. `out_orig` must be a valid writable pointer.
pub unsafe fn hook_sym(
    lib: &core::ffi::CStr,
    sym: &core::ffi::CStr,
    new_fn: *mut c_void,
    out_orig: *mut *mut c_void,
) -> *mut c_void {
    unsafe { shadowhook_hook_sym_name(lib.as_ptr(), sym.as_ptr(), new_fn, out_orig) }
}
