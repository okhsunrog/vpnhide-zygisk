//! Build-time glue: compile ByteDance shadowhook (our fork) from source via
//! CMake and link the resulting static archive into this cdylib.
//!
//! The fork lives at `third_party/android-inline-hook` (git submodule,
//! branch `vpnhide-zygisk`) and adds two things on top of upstream:
//!
//!   1. a `SHADOWHOOK_STATIC=ON` CMake option that builds `libshadowhook.a`
//!      instead of a shared library and drops the SHARED-only link flags;
//!   2. a stub `sh_linker_init()` so `shadowhook_init()` doesn't fail on
//!      Android 16 with `SHADOWHOOK_ERRNO_INIT_LINKER`.
//!
//! See the fork's commit message for the full rationale.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=third_party/android-inline-hook/shadowhook/src/main/cpp");

    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("android") {
        // Host builds (cargo check / unit tests on linux-gnu) don't link
        // the Android cdylib; skip the whole native build step.
        return;
    }
    if !target.starts_with("aarch64") {
        panic!("vpnhide-zygisk currently only supports aarch64-linux-android (target={target})");
    }

    // cargo-ndk sets ANDROID_NDK_HOME before invoking us.
    let ndk = env::var("ANDROID_NDK_HOME")
        .or_else(|_| env::var("ANDROID_NDK_ROOT"))
        .or_else(|_| env::var("NDK_HOME"))
        .expect("ANDROID_NDK_HOME must be set (cargo-ndk normally does this)");

    let toolchain_file = PathBuf::from(&ndk).join("build/cmake/android.toolchain.cmake");
    assert!(
        toolchain_file.is_file(),
        "NDK CMake toolchain not found at {}",
        toolchain_file.display()
    );

    let shadowhook_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("third_party/android-inline-hook/shadowhook/src/main/cpp");
    assert!(
        shadowhook_src.join("CMakeLists.txt").is_file(),
        "shadowhook submodule not initialized — run `git submodule update --init --recursive`"
    );

    // Build the static archive via the `cmake` crate. It picks up the NDK
    // toolchain and runs `cmake --build`. `no_build_target(true)` skips the
    // default `install` step (upstream has no install() rules) and lets us
    // pin the exact CMake target to build.
    let dst = cmake::Config::new(&shadowhook_src)
        .define("CMAKE_TOOLCHAIN_FILE", &toolchain_file)
        .define("ANDROID_ABI", "arm64-v8a")
        .define("ANDROID_PLATFORM", "android-24")
        .define("SHADOWHOOK_STATIC", "ON")
        .no_build_target(true)
        .build_target("shadowhook")
        .build();

    // cmake crate puts build artifacts under `<out>/build/`.
    let build_dir = dst.join("build");
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=shadowhook");
    println!("cargo:rustc-link-lib=log");

    // shadowhook's inline-patching code emits a libcall to `__clear_cache`
    // (I-cache flush after rewriting instructions). Rust's own
    // `compiler_builtins` doesn't export that symbol on aarch64-android,
    // so without this the cdylib has an unresolved reference and the
    // dynamic linker rejects it at dlopen time:
    //   cannot locate symbol "__clear_cache" referenced by ...
    // Pull it from the NDK's compiler-rt builtins archive.
    if let Some(builtins) = find_ndk_builtins(&ndk) {
        println!("cargo:rustc-link-arg={}", builtins.display());
    } else {
        println!(
            "cargo:warning=libclang_rt.builtins-aarch64-android.a not found under {ndk}; \
             __clear_cache may be unresolved at dlopen time"
        );
    }
}

/// Locate `libclang_rt.builtins-aarch64-android.a` inside an NDK tree.
/// Typical layout: `<ndk>/toolchains/llvm/prebuilt/<host>/lib/clang/<ver>/lib/linux/…`.
fn find_ndk_builtins(ndk: &str) -> Option<PathBuf> {
    let base = PathBuf::from(ndk).join("toolchains/llvm/prebuilt");
    for host in std::fs::read_dir(&base).ok()?.flatten() {
        let clang_dir = host.path().join("lib/clang");
        let Ok(versions) = std::fs::read_dir(&clang_dir) else { continue };
        for v in versions.flatten() {
            let candidate = v
                .path()
                .join("lib/linux/libclang_rt.builtins-aarch64-android.a");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}
