//! vpnhide-zygisk — a Zygisk (NeoZygisk) module that hides an active
//! Android VPN from selected apps by hooking the libc network-introspection
//! syscalls that the apps use to detect `tun0`/`wg0`/etc.
//!
//! ## High-level flow
//!
//! 1. **`on_load`** — stash nothing, just log. The target app's native
//!    libraries aren't loaded yet at this stage so we can't PLT-hook them.
//! 2. **`preAppSpecialize`** — we get told which app is about to be forked
//!    (via `args.nice_name`). Look up the package name against our
//!    allowlist file (`/data/adb/modules/vpnhide_zygisk/targets.txt`). If
//!    the current app isn't in the list, set `DlcloseModuleLibrary` and
//!    return — the module is unloaded cleanly after specialization. If
//!    it IS in the list, stash a flag and wait for post-specialize.
//! 3. **`postAppSpecialize`** — the app's main native libraries have now
//!    been loaded into the process. Parse `/proc/self/maps`, collect every
//!    distinct ELF file backing an executable mapping, and register a PLT
//!    hook on each that redirects `ioctl` to our replacement function.
//!    Commit the hooks. From this point on, any call from any loaded
//!    library into libc's `ioctl` goes through our filter.
//!
//! ## Module metadata
//!
//! The KernelSU module install script places this shared library at
//! `/data/adb/modules/vpnhide_zygisk/zygisk/arm64-v8a.so`. NeoZygisk
//! injects it into every forked app process; the `preAppSpecialize` filter
//! ensures we only actually do work for targeted apps.

mod filter;
mod hooks;
mod shadowhook;

use std::fs;

use jni::JNIEnv;
use zygisk_api::ZygiskModule;
use zygisk_api::api::v5::{AppSpecializeArgs, V5, ZygiskOption};
use zygisk_api::api::ZygiskApi;

use crate::hooks::{hooked_ioctl, set_real_ioctl_ptr};

const LOG_TAG: &core::ffi::CStr = c"vpnhide-zygisk";
const TARGETS_FILE: &str = "/data/adb/modules/vpnhide_zygisk/targets.txt";

/// Log at INFO level via Android's liblog. Small shim that avoids pulling
/// in `log`/`android_logger`, keeping the .so tiny.
fn logi(msg: &str) {
    let c = std::ffi::CString::new(msg).unwrap_or_default();
    unsafe {
        __android_log_print(LogPriority::INFO as i32, LOG_TAG.as_ptr(), c"%s".as_ptr(), c.as_ptr());
    }
}
fn logw(msg: &str) {
    let c = std::ffi::CString::new(msg).unwrap_or_default();
    unsafe {
        __android_log_print(LogPriority::WARN as i32, LOG_TAG.as_ptr(), c"%s".as_ptr(), c.as_ptr());
    }
}
fn loge(msg: &str) {
    let c = std::ffi::CString::new(msg).unwrap_or_default();
    unsafe {
        __android_log_print(LogPriority::ERROR as i32, LOG_TAG.as_ptr(), c"%s".as_ptr(), c.as_ptr());
    }
}

#[repr(i32)]
#[allow(dead_code)]
enum LogPriority {
    VERBOSE = 2,
    DEBUG = 3,
    INFO = 4,
    WARN = 5,
    ERROR = 6,
}

unsafe extern "C" {
    fn __android_log_print(
        prio: core::ffi::c_int,
        tag: *const core::ffi::c_char,
        fmt: *const core::ffi::c_char,
        ...
    ) -> core::ffi::c_int;
}

/// The module struct. Held as a `Default` singleton by the
/// `register_module!` macro.
#[derive(Default)]
pub struct VpnHide {
    /// Set by `preAppSpecialize` if the forked process is a target we want
    /// to hook. Read by `postAppSpecialize`. Accessed single-threaded
    /// (Zygisk calls pre/post sequentially on the zygote main thread).
    is_target: core::cell::Cell<bool>,
}

// Single-threaded access by construction.
unsafe impl Sync for VpnHide {}

impl ZygiskModule for VpnHide {
    type Api = V5;

    fn on_load(&self, _api: ZygiskApi<'_, V5>, _env: JNIEnv<'_>) {
        logi("on_load");
    }

    fn pre_app_specialize<'a>(
        &self,
        mut api: ZygiskApi<'a, V5>,
        env: JNIEnv<'a>,
        args: &'a mut AppSpecializeArgs<'_>,
    ) {
        // pre_app_specialize runs on the zygote side BEFORE uid drop, so
        // we can still read /data/adb/modules/... targets.txt here. Read
        // nice_name, gate on the allowlist, and either set the flag or
        // tell Zygisk to dlclose us after this callback returns.
        let package = read_jstring(&env, args.nice_name);
        match package.as_deref() {
            Some(p) if is_targeted(p) => {
                logi(&format!("pre_app_specialize: targeting {p}"));
                self.is_target.set(true);
            }
            _ => {
                // Not a target. Unload on return to reclaim memory.
                self.is_target.set(false);
                mark_cleanup(&mut api);
            }
        }
    }

    fn post_app_specialize<'a>(
        &self,
        _api: ZygiskApi<'a, V5>,
        _env: JNIEnv<'a>,
        _args: &'a AppSpecializeArgs<'_>,
    ) {
        if !self.is_target.get() {
            return;
        }
        match install_hooks() {
            Ok(()) => logi("hooks installed (inline libc!ioctl)"),
            Err(err) => loge(&format!("install_hooks failed: {err}")),
        }
    }

    // No pre_server_specialize override — the trait default is empty,
    // which is what we want: system_server isn't in scope for this module.
}

/// Tell Zygisk to `dlclose` our .so once the current callback returns.
/// Saves memory in every process where we don't actually hook anything.
fn mark_cleanup(api: &mut ZygiskApi<'_, V5>) {
    api.set_option(ZygiskOption::DlCloseModuleLibrary);
}

/// Install an inline hook on `libc.so!ioctl` via ByteDance shadowhook.
///
/// This replaces the earlier PLT-hook approach. PLT hooks can only patch
/// callers that are already mapped at `post_app_specialize` time — which
/// excludes `libflutter.so`/`libapp.so` and any other library loaded later
/// via `dlopen`. Inline-hooking libc's `ioctl` entry point itself catches
/// every caller regardless of load order.
fn install_hooks() -> Result<(), String> {
    shadowhook::init_once().map_err(|rc| format!("shadowhook_init: rc={rc}"))?;

    let mut orig: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: `hooked_ioctl` is ABI-compatible with libc `ioctl`; `orig`
    // is a valid writable pointer.
    let stub = unsafe {
        shadowhook::hook_sym(
            c"libc.so",
            c"ioctl",
            hooked_ioctl as *mut core::ffi::c_void,
            &mut orig,
        )
    };
    if stub.is_null() {
        return Err("shadowhook_hook_sym_name(libc.so, ioctl) returned null".into());
    }
    if orig.is_null() {
        return Err("shadowhook returned null original trampoline".into());
    }
    set_real_ioctl_ptr(orig as *const ());
    Ok(())
}

/// Is this package on our allowlist?
///
/// Called from `pre_app_specialize`, which runs on the zygote side BEFORE
/// the uid drop and SELinux context transition, so `/data/adb/modules/...`
/// is still readable here. Also keeps a small hardcoded allowlist as a
/// convenience so the module works out-of-the-box for the primary use case.
#[inline(never)]
fn is_targeted(package: &str) -> bool {

    // Direct string comparisons — clearer, and easier to extend by hand.
    if package == "ru.plazius.shokoladnica" {
        logi("is_targeted: matched shokoladnica (main)");
        return true;
    }
    if package == "ru.plazius.shokoladnica:AppMetrica" {
        logi("is_targeted: matched shokoladnica (AppMetrica)");
        return true;
    }
    if package.starts_with("ru.plazius.shokoladnica") {
        logi("is_targeted: matched shokoladnica (subprocess)");
        return true;
    }

    match fs::read_to_string(TARGETS_FILE) {
        Ok(content) => {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line == package {
                    return true;
                }
            }
            false
        }
        Err(e) => {
            logw(&format!(
                "is_targeted: can't read {TARGETS_FILE} ({e}); using hardcoded list only"
            ));
            false
        }
    }
}

/// Decode a `JString` (as stored in `AppSpecializeArgs::nice_name`) into
/// an owned Rust `String`. Returns None on any failure.
fn read_jstring<'a>(env: &JNIEnv<'a>, jstr: &jni::objects::JString<'a>) -> Option<String> {
    if jstr.is_null() {
        return None;
    }
    let mut env_clone = unsafe { env.unsafe_clone() };
    env_clone
        .get_string(jstr)
        .ok()
        .and_then(|s| s.to_str().ok().map(|s| s.to_string()))
}

zygisk_api::register_module!(VpnHide);

// Empty companion — declared so we don't have to recompile the .so if we
// ever want to add a root-privileged helper later.
zygisk_api::register_companion!(|_| ());
