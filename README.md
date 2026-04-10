# vpnhide-zygisk

A small Zygisk module written in Rust that hides an active VPN interface
from selected Android apps by inline-hooking libc's `ioctl`.

Companion to the [Kotlin LSPosed module `vpnhide`](https://github.com/okhsunrog/vpnhide),
which handles Java-level VPN detection. This module covers the **native**
detection path — apps calling `ioctl(SIOCGIFNAME)` / `ioctl(SIOCGIFFLAGS)`
from C/C++/JNI/Flutter runtime code that never enters ART.

## Status

Working on Android 16 (API 36) with KernelSU-Next + NeoZygisk. Verified
against `ru.plazius.shokoladnica` (the Flutter-based cafe loyalty app that
motivated this module): the VPN-detection banner no longer appears when a
WireGuard tunnel is active.

Current coverage:
- `ioctl(SIOCGIFFLAGS)` — pre-screened; returns `-1 ENODEV` if the caller
  hands us an `ifr_name` matching a VPN prefix.
- `ioctl(SIOCGIFNAME)` — called through; if the returned name is a VPN,
  rewritten to `-1 ENODEV`.
- Any other `ioctl` request: passthrough.

Planned:
- `getifaddrs` / `freeifaddrs` filter (Dart VM's `NetworkInterface.list()`).
- `ioctl(SIOCGIFCONF)` bulk-query filter.
- `recvmsg` filter on `NETLINK_ROUTE` sockets.

## Architecture

The module runs inside each forked app process via NeoZygisk.

1. **`pre_app_specialize`** — runs on the zygote side before uid drop and
   SELinux context transition. We read the package name from
   `args.nice_name`, check it against `/data/adb/modules/vpnhide_zygisk/targets.txt`
   plus a small built-in allowlist, and either:
   - set an internal `is_target` flag, or
   - call `DlCloseModuleLibrary` so Zygisk unloads our `.so` from the
     process on callback return (non-targeted apps pay zero cost).
2. **`post_app_specialize`** — on targeted processes only: initialize
   ByteDance shadowhook and install a single inline hook on
   `libc.so!ioctl`. From this point on, every caller in the process —
   regardless of when its library was dlopen'd — ends up in our
   `hooked_ioctl` replacement.

### Why inline hooking instead of PLT

PLT hooks patch the caller library's procedure linkage table entry for a
given symbol. To intercept `libflutter.so`'s call to `ioctl` that way we'd
have to patch libflutter.so's PLT.

At `post_app_specialize` — the last Zygisk callback before the app's Java
code runs — libflutter.so / libapp.so / the Dart VM's native code are
**not yet loaded**. Only the ~350 Android system libraries are mapped, and
none of them directly call `ioctl` from their own code (verified via
`readelf -r` on libandroid, libbinder, libutils, libmedia, libui, libgui,
libnetd_client, libbase, libcutils, libc++, libandroid_runtime, libart —
zero ioctl relocations across all of them). The ioctl call sites are
inside libc itself.

Inline-hooking libc.so's `ioctl` entry point rewrites the first few
instructions of the function in-place. Any caller in the process — Flutter,
any JNI library, anything dlopen'd later — eventually jumps to that same
address and lands on our trampoline. Load order becomes irrelevant. The
only thing inline libc hooks don't catch is apps issuing `syscall(SYS_ioctl, …)`
directly, which is extremely rare outside of deliberate anti-hook code.

### shadowhook fork

Inline hooking is provided by [ByteDance shadowhook](https://github.com/bytedance/android-inline-hook).
We carry a small fork at [okhsunrog/android-inline-hook](https://github.com/okhsunrog/android-inline-hook)
(branch `vpnhide-zygisk`), vendored as a git submodule under
`third_party/android-inline-hook/`, with two changes on top of upstream:

1. **`SHADOWHOOK_STATIC=ON` CMake option** — builds `libshadowhook.a`
   instead of a shared library so we can embed it directly into this
   Rust cdylib, and drops the SHARED-only link options.
2. **`sh_linker_init()` stub** — upstream hooks the Android dynamic linker's
   `soinfo::call_constructors` / `soinfo::call_destructors` so it can apply
   "pending" hooks to libraries dlopen'd after init. On Android 16 (API 36)
   the hardcoded symbol table in `sh_linker_hook_call_ctors_dtors()` no
   longer matches the newer linker layout, and the call fails with
   `SHADOWHOOK_ERRNO_INIT_LINKER`, blocking all subsequent hooks. We don't
   use the pending-hook feature (our target libc.so is always preloaded),
   so the stub skips this path entirely.

## Build

Requirements:

- Rust ≥ 1.85 (edition 2024)
- `rustup target add aarch64-linux-android`
- `cargo install cargo-ndk`
- Android NDK (auto-detected under `~/Android/Sdk/ndk/`; any recent NDK
  that ships `libclang_rt.builtins-aarch64-android.a` works)
- CMake ≥ 3.22, Ninja
- `git submodule update --init --recursive`

Build & package:

```bash
./build-zip.sh
# Output: target/vpnhide-zygisk.zip (~180 KB)
```

`build.rs` invokes the NDK's CMake toolchain on the shadowhook submodule,
pulls in `libclang_rt.builtins-aarch64-android.a` for `__clear_cache`,
and statically links everything into `libvpnhide_zygisk.so`.

## Install

1. `adb push target/vpnhide-zygisk.zip /sdcard/Download/`
2. KernelSU-Next manager → Modules → Install from storage → pick the zip
3. Reboot
4. Edit `/data/adb/modules/vpnhide_zygisk/targets.txt` to add your target
   apps (one package name per line, `#` for comments):

   ```
   ru.plazius.shokoladnica
   com.example.targetapp
   ```

5. Force-stop the target app(s) so they re-fork with the hooks active:
   `adb shell am force-stop <pkg>`
6. Verify via `adb logcat | grep vpnhide-zygisk`. Expected lines:

   ```
   I vpnhide-zygisk: is_targeted: matched shokoladnica (main)
   I vpnhide-zygisk: pre_app_specialize: targeting ru.plazius.shokoladnica
   E shadowhook_tag: shadowhook init(default_mode: UNIQUE, …), return: 0
   I vpnhide-zygisk: hooks installed (inline libc!ioctl)
   ```

## Filter logic

VPN interface prefixes: `tun`, `ppp`, `tap`, `wg`, `ipsec`, `xfrm`, `utun`,
`l2tp`, `gre`, plus anything containing the substring `vpn`. Matches the
list in the Kotlin companion module.

- **`SIOCGIFFLAGS`** (app already has a name, wants flags): if the input
  `ifr_name` matches a VPN prefix, set `errno=ENODEV` and return `-1`
  without touching the real ioctl. The kernel never tells the app that
  `tun0` has `IFF_POINTOPOINT` / `IFF_RUNNING`.
- **`SIOCGIFNAME`** (app has an index, wants the name): call the real
  ioctl, check the returned name. If it's a VPN, rewrite to `-1 ENODEV`.
  The app sees an empty slot at that index and moves on.
- Any other request passes through unchanged.

## Uninstall

KernelSU-Next manager → Modules → VPN Hide (Zygisk native) → Remove.
Reboot.

## Files

- `src/lib.rs` — module entry point, scope file handling, hook installer
- `src/hooks.rs` — `hooked_ioctl` replacement + errno helper
- `src/filter.rs` — VPN interface name matching (unit tested)
- `src/shadowhook.rs` — minimal FFI to shadowhook
- `build.rs` — drives CMake on the shadowhook submodule
- `third_party/android-inline-hook/` — submodule (our shadowhook fork)
- `module/` — KernelSU/Magisk module metadata
- `build-zip.sh` — cross-compile + package script

## License

0BSD — do whatever you want with it, no warranty.
