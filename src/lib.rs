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
mod maps;

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
        let Some(package) = read_jstring(&env, args.nice_name) else {
            mark_cleanup(&mut api);
            return;
        };

        if !is_targeted(&package) {
            mark_cleanup(&mut api);
            return;
        }

        logi(&format!("pre_app_specialize: targeting {}", package));
        self.is_target.set(true);
    }

    fn post_app_specialize<'a>(
        &self,
        mut api: ZygiskApi<'a, V5>,
        _env: JNIEnv<'a>,
        _args: &'a AppSpecializeArgs<'_>,
    ) {
        if !self.is_target.get() {
            return;
        }
        match install_hooks(&mut api) {
            Ok(count) => logi(&format!("hooks installed across {count} libraries")),
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

/// Install PLT hooks for `ioctl` on every currently-mapped ELF in the
/// process. Returns the number of libraries we registered a hook for.
fn install_hooks(api: &mut ZygiskApi<'_, V5>) -> Result<usize, String> {
    let elfs = maps::loaded_elfs();
    if elfs.is_empty() {
        return Err("no ELFs found in /proc/self/maps".into());
    }

    // Zygisk's `pltHookRegister` is the same helper for every library:
    // the saved old pointer is overwritten on each register call, but
    // since all these PLT entries resolve to the same libc export of
    // `ioctl`, the pointer stored is always the same. Grab whatever's
    // there after the last register call.
    let mut old_fn: *const () = core::ptr::null();
    let new_fn: *const () = hooked_ioctl as *const ();

    let mut registered = 0usize;
    for elf in &elfs {
        // Skip our own shared library — we don't want to redirect ioctl
        // calls made from inside this module.
        if elf
            .path
            .to_str()
            .map(|s| s.contains("vpnhide_zygisk"))
            .unwrap_or(false)
        {
            continue;
        }
        unsafe {
            api.plt_hook_register(elf.dev, elf.inode, c"ioctl", new_fn, &mut old_fn);
        }
        registered += 1;
    }
    if registered == 0 {
        return Err("no hooks registered — empty candidate set".into());
    }

    api.plt_hook_commit()
        .map_err(|e| format!("plt_hook_commit: {e:?}"))?;

    if old_fn.is_null() {
        // This can happen if none of the libraries we tried actually had
        // a PLT entry for `ioctl`. Log but don't treat as fatal — maybe
        // the app will call ioctl from a library loaded later via dlopen
        // and we can catch it on a second pass if we add that later.
        logw("plt_hook_commit succeeded but no old_fn was returned");
    } else {
        set_real_ioctl_ptr(old_fn);
    }
    Ok(registered)
}

/// Is this package on our allowlist?
///
/// Reads `/data/adb/modules/vpnhide_zygisk/targets.txt` fresh every time
/// a process is specialized. The file is a few hundred bytes at most,
/// rarely changed, and we avoid stale cache issues by not caching.
fn is_targeted(package: &str) -> bool {
    let Ok(content) = fs::read_to_string(TARGETS_FILE) else {
        return false;
    };
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
