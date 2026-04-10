//! The actual libc hook functions.
//!
//! These are called INSTEAD OF the real libc symbols from any PLT we've
//! patched. Each hook calls the saved original function via a function
//! pointer stored in `statics` after `pltHookRegister` ran. We can't rely
//! on linkage-time names like `libc::ioctl` because those would resolve
//! back through our own PLT entry — which would either recurse infinitely
//! or, in a different library's process, not be hooked at all.
//!
//! ## Important safety notes
//!
//! * The `*const ()` function pointers used by Zygisk's PLT hook API are
//!   variadic in C (`ioctl` is `int ioctl(int fd, unsigned long req, ...)`)
//!   but Rust doesn't have first-class variadic functions. We work around
//!   this by declaring the relevant `ioctl` signatures we care about
//!   (`SIOCGIFNAME`, `SIOCGIFFLAGS`) as 3-argument forms and trusting the
//!   ABI — that's what the rest of the world does.
//! * The hook must be reentrant-safe. It WILL be called from arbitrary
//!   threads, before `main()`, from signal handlers in the worst case.
//!   No `println!`, no locks that could deadlock, no allocation unless
//!   absolutely necessary.
//! * If anything fails inside a hook, we fall back to calling the
//!   original. Panicking would abort the entire process.

use core::cell::Cell;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicPtr, Ordering};

use libc::{SIOCGIFFLAGS, SIOCGIFNAME, ifreq};

use crate::filter::is_vpn_iface_bytes;

// Thread-local guard: set by hooked_getifaddrs before calling the real
// getifaddrs, cleared after. While set, hooked_ioctl passes through
// without filtering. This prevents our ioctl hook from interfering with
// libc's INTERNAL ioctl(SIOCGIFFLAGS) calls made inside getifaddrs() —
// those calls are redundant (getifaddrs hook filters the result anyway)
// and harmful (returning ENODEV breaks libc's ifaddrs list construction,
// causing errors like `ioctl(SIOCGIFFLAGS) for "tun0" failed in ifaddrs`
// and corrupting NFC/HCE payment flows).
thread_local! {
    static IN_GETIFADDRS: Cell<bool> = const { Cell::new(false) };
}

// Android bionic exposes the thread-local errno via `int *__errno()`.
// The `libc` crate doesn't re-export this symbol for android targets,
// so declare it ourselves. Matches bionic's prototype exactly.
unsafe extern "C" {
    fn __errno() -> *mut c_int;
}

#[inline(always)]
fn set_errno(val: c_int) {
    unsafe {
        *__errno() = val;
    }
}

// ============================================================================
//  Saved originals
// ============================================================================

/// Pointer to the real `ioctl` entrypoint, captured by `pltHookRegister`.
/// Stored as `AtomicPtr<c_void>` so the hook can load it with a relaxed
/// atomic read — no locks.
static REAL_IOCTL: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// Raw function type for the slice of ioctl variants we care about.
/// Matches the three-argument C signature `int ioctl(int, unsigned long, void*)`.
type IoctlFn = unsafe extern "C" fn(c_int, libc::c_ulong, *mut c_void) -> c_int;

/// Safely fetch the saved original ioctl. Returns None if for some reason
/// the pointer is null (should never happen after install, but defensive).
#[inline(always)]
fn real_ioctl() -> Option<IoctlFn> {
    let raw = REAL_IOCTL.load(Ordering::Relaxed);
    if raw.is_null() {
        None
    } else {
        // SAFETY: we only ever store a valid function pointer of this shape
        // in this slot via set_real_ioctl_ptr.
        Some(unsafe { core::mem::transmute::<*mut c_void, IoctlFn>(raw) })
    }
}

/// Stash the original pointer we got back from `pltHookRegister`.
pub fn set_real_ioctl_ptr(p: *const ()) {
    REAL_IOCTL.store(p as *mut c_void, Ordering::Relaxed);
}

// ============================================================================
//  Hook: ioctl
// ============================================================================

/// Replacement for `libc::ioctl`.
///
/// Handles:
/// * `SIOCGIFNAME` — called with `ifr_ifindex` to translate an index to an
///   interface name. If the real result is a VPN name, we rewrite it to
///   look like the index doesn't exist by setting errno=ENODEV and
///   returning -1. The app treats that like "no interface at this index"
///   and moves on.
/// * `SIOCGIFFLAGS` — called with `ifr_name` to get the flags of a specific
///   interface. If the input name is already a VPN, we short-circuit with
///   errno=ENODEV WITHOUT calling the real ioctl (so the kernel never tells
///   us the flags include `IFF_POINTOPOINT` and similar tells).
///
/// Any other request falls straight through to the real ioctl unchanged.
///
/// # Safety
///
/// Called from native code via a PLT trampoline. The variadic third argument
/// is promoted to `*mut c_void` — for our two SIOCGIF* requests it always
/// points to a `struct ifreq`, which is what bionic's headers declare.
pub unsafe extern "C" fn hooked_ioctl(
    fd: c_int,
    request: libc::c_ulong,
    arg: *mut c_void,
) -> c_int {
    let Some(real) = real_ioctl() else {
        // Original pointer missing — fail closed rather than crash.
        set_errno(libc::EFAULT);
        return -1;
    };

    // If we're inside a hooked_getifaddrs call on this thread, pass
    // through without filtering. See the IN_GETIFADDRS doc comment.
    if IN_GETIFADDRS.with(|f| f.get()) {
        return unsafe { real(fd, request, arg) };
    }

    // SIOCGIFFLAGS — the app has a name and wants flags. Pre-screen input.
    if request == SIOCGIFFLAGS as libc::c_ulong {
        if !arg.is_null() {
            // SAFETY: Linux contract for SIOCGIFFLAGS says arg points to a
            // fully-owned `struct ifreq` the caller allocated. We only read
            // the `ifr_name` union member (a 16-byte [c_char; 16]).
            let req = unsafe { &*(arg as *const ifreq) };
            let name_bytes = unsafe {
                &*(&req.ifr_name as *const [libc::c_char] as *const [u8])
            };
            if is_vpn_iface_bytes(name_bytes) {
                set_errno(libc::ENODEV);
                return -1;
            }
        }
        return unsafe { real(fd, request, arg) };
    }

    // SIOCGIFNAME — the app has an index and wants a name. Call through,
    // then filter the result.
    if request == SIOCGIFNAME as libc::c_ulong {
        let ret = unsafe { real(fd, request, arg) };
        if ret == 0 && !arg.is_null() {
            let req = unsafe { &*(arg as *const ifreq) };
            let name_bytes = unsafe {
                &*(&req.ifr_name as *const [libc::c_char] as *const [u8])
            };
            if is_vpn_iface_bytes(name_bytes) {
                set_errno(libc::ENODEV);
                return -1;
            }
        }
        return ret;
    }

    // Anything else: pass through unmodified.
    unsafe { real(fd, request, arg) }
}

// ============================================================================
//  Hook: getifaddrs
// ============================================================================

/// Pointer to the real `getifaddrs`, captured at install time.
static REAL_GETIFADDRS: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

type GetifaddrsFn = unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> c_int;

#[inline(always)]
fn real_getifaddrs() -> Option<GetifaddrsFn> {
    let raw = REAL_GETIFADDRS.load(Ordering::Relaxed);
    if raw.is_null() {
        None
    } else {
        // SAFETY: we only ever store a valid `getifaddrs` pointer in this
        // slot via `set_real_getifaddrs_ptr`.
        Some(unsafe { core::mem::transmute::<*mut c_void, GetifaddrsFn>(raw) })
    }
}

/// Stash the trampoline returned by shadowhook for `libc.so!getifaddrs`.
pub fn set_real_getifaddrs_ptr(p: *const ()) {
    REAL_GETIFADDRS.store(p as *mut c_void, Ordering::Relaxed);
}

/// Replacement for `libc::getifaddrs`.
///
/// Calls the real `getifaddrs`, then walks the returned linked list and
/// unlinks every entry whose `ifa_name` matches a VPN prefix. The caller
/// still calls `freeifaddrs` on the head pointer we return; it walks only
/// via `ifa_next`, so unlinked (VPN) nodes are leaked — a handful of
/// ~200-byte `struct ifaddrs` per `getifaddrs` call, which is acceptable
/// in exchange for not having to track a per-allocation shadow list. We
/// do not hook `freeifaddrs` for this reason.
///
/// Covers:
/// * native callers of `getifaddrs` directly from C/C++/NDK code;
/// * the Android libcore path: `java.net.NetworkInterface.getNetworkInterfaces()`
///   internally calls `getifaddrs` through a JNI shim (`Libcore.os`), so
///   this hook also catches Kotlin/Java apps if for some reason the
///   Java-level LSPosed hook didn't fire first.
///
/// # Safety
///
/// Called from native code. `ifap` is a valid out-pointer the caller
/// owns; on success the real `getifaddrs` fills it with a pointer to a
/// caller-owned linked list that we are free to mutate before returning.
pub unsafe extern "C" fn hooked_getifaddrs(ifap: *mut *mut libc::ifaddrs) -> c_int {
    let Some(real) = real_getifaddrs() else {
        set_errno(libc::EFAULT);
        return -1;
    };

    // Set the thread-local guard so hooked_ioctl passes through while
    // libc's real getifaddrs runs (it internally calls ioctl for each
    // interface to get flags — we must not filter those).
    IN_GETIFADDRS.with(|f| f.set(true));
    let rc = unsafe { real(ifap) };
    IN_GETIFADDRS.with(|f| f.set(false));

    if rc != 0 || ifap.is_null() {
        return rc;
    }

    // Walk the list using a "previous next-pointer slot" cursor so
    // unlinking the head works the same as unlinking an interior node.
    // `slot` always points at the ifa_next field (or the out-pointer *ifap
    // on the first iteration) whose value is the current entry.
    let mut slot: *mut *mut libc::ifaddrs = ifap;
    unsafe {
        while !(*slot).is_null() {
            let entry = *slot;
            let name_ptr = (*entry).ifa_name;
            let is_vpn = if name_ptr.is_null() {
                false
            } else {
                let name = core::ffi::CStr::from_ptr(name_ptr);
                crate::filter::is_vpn_iface_cstr(name)
            };
            if is_vpn {
                *slot = (*entry).ifa_next;
                // `entry` is intentionally leaked; see the doc comment.
            } else {
                slot = &mut (*entry).ifa_next;
            }
        }
    }

    rc
}
