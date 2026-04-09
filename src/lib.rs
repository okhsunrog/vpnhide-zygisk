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
        _api: ZygiskApi<'a, V5>,
        _env: JNIEnv<'a>,
        _args: &'a mut AppSpecializeArgs<'_>,
    ) {
        // DIAGNOSTIC: minimal pre — no JNI, no file IO, no format!.
        // Unconditionally mark as target. post_app_specialize will gate
        // on the targets.txt file (safer there — we read via std::fs with
        // mount namespace fully set up).
        logi("pre_app_specialize: MINIMAL mode, marking as potential target");
        self.is_target.set(true);
    }

    fn post_app_specialize<'a>(
        &self,
        mut api: ZygiskApi<'a, V5>,
        env: JNIEnv<'a>,
        args: &'a AppSpecializeArgs<'_>,
    ) {
        logi("post_app_specialize: ENTER");
        if !self.is_target.get() {
            return;
        }

        // Read nice_name here (not in pre — seems to interact badly with
        // zygote state). At post_app_specialize the app process is fully
        // specialized and JNI is in a known-good state.
        let package = match read_jstring(&env, args.nice_name) {
            Some(p) => p,
            None => {
                logw("post_app_specialize: failed to read nice_name, skipping");
                return;
            }
        };
        logi(&format!("post_app_specialize: package={package}"));

        if !is_targeted(&package) {
            logi("post_app_specialize: not in targets.txt, skipping");
            return;
        }

        logi("post_app_specialize: about to install_hooks");
        match install_hooks(&mut api) {
            Ok(count) => logi(&format!("hooks installed across {count} libraries")),
            Err(err) => loge(&format!("install_hooks failed: {err}")),
        }
        logi("post_app_specialize: EXIT");
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
    logi("install_hooks: reading /proc/self/maps");
    let elfs = maps::loaded_elfs();
    logi(&format!(
        "install_hooks: found {} total ELF mappings (pre-filter)",
        elfs.len()
    ));
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

    // STATUS (2026-04-10): PLT hooking via Zygisk fundamentally does not
    // solve the Flutter case and is left here as a skeleton for future
    // work. The problem is a timing/visibility issue, not a code bug:
    //
    //   1. Zygisk's pltHookRegister patches PLT entries in libraries
    //      currently mapped into the process. It cannot patch libraries
    //      that load later (e.g. via dlopen).
    //
    //   2. At post_app_specialize time, libflutter.so / libapp.so / the
    //      Dart VM's native code are NOT yet loaded. Only ~350 Android
    //      system libraries are mapped.
    //
    //   3. Those ~350 system libraries do NOT directly call libc::ioctl
    //      from their own code. They link against libc but the ioctl
    //      call is wrapped inside libc itself. Running `readelf -r` over
    //      a dozen common system libs (libandroid, libbinder, libutils,
    //      libmedia, libui, libgui, libnetd_client, libbase, libcutils,
    //      libc++, libandroid_runtime, libart) shows ZERO ioctl
    //      relocations. So `pltHookRegister(..., "ioctl", ...)` on a
    //      system library either (a) finds nothing to patch and commit
    //      returns PltHookCommitError, or (b) patches a different
    //      library's PLT via some cascading side effect, crashing the
    //      process (observed when hooking 349 libraries at once).
    //
    //   4. The correct architectural fix is one of:
    //        a) inline-hook libc.so's `ioctl` entry point itself via
    //           ByteDance shadowhook or Dobby. This catches every caller
    //           regardless of load order. Requires FFI to a C++ library.
    //        b) hook `dlopen` / `android_dlopen_ext` in the system
    //           libraries that do call them (libandroid_runtime.so
    //           uses dlopen when the Java VM calls System.loadLibrary),
    //           then inside our wrapper, after the real dlopen returns,
    //           re-scan /proc/self/maps and register new PLT hooks on
    //           the freshly loaded library. Requires persistent access
    //           to the Zygisk API table outside the specialize
    //           callbacks.
    //
    // For now we register a no-op "single library" hook on libandroid.so
    // so that the install_hooks path is exercised end to end. This lets
    // us verify that the scoping, pre/post specialize flow, and PLT
    // registration plumbing are all working, even though the actual
    // interception is not effective.
    let target_substr = "libandroid.so";
    let mut registered = 0usize;
    for elf in &elfs {
        let Some(path) = elf.path.to_str() else { continue };

        // Skip our own .so and framework libraries.
        if path.contains("vpnhide_zygisk")
            || path.contains("libvector")
            || path.contains("liblspd")
            || path.contains("zygisk")
            || path.contains("linker64")
            || path.contains("ld-android")
        {
            continue;
        }

        if !path.ends_with(target_substr) {
            continue;
        }

        logi(&format!("install_hooks: targeting single lib: {path}"));
        unsafe {
            api.plt_hook_register(elf.dev, elf.inode, c"ioctl", new_fn, &mut old_fn);
        }
        registered += 1;
    }
    logi(&format!(
        "install_hooks: registered ioctl hook on {registered} libraries"
    ));
    if registered == 0 {
        return Err("no hooks registered — empty candidate set".into());
    }
    logi(&format!(
        "install_hooks: about to plt_hook_commit {} registrations",
        registered
    ));

    api.plt_hook_commit()
        .map_err(|e| format!("plt_hook_commit: {e:?}"))?;
    logi("install_hooks: plt_hook_commit returned OK");

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
/// Reads `/data/adb/modules/vpnhide_zygisk/targets.txt` every time — but
/// that path is inside `/data/adb/` which is root-only (SELinux
/// `adb_data_file` label), and by the time we're in `post_app_specialize`
/// the process has been specialized into the app's context
/// (`untrusted_app`) which can't read it. Falls back to a hardcoded
/// allowlist so the module still works when the file read fails.
#[inline(never)]
fn is_targeted(package: &str) -> bool {
    logi(&format!("is_targeted check: '{package}'"));

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
