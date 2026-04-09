# vpnhide-zygisk

A tiny Zygisk module in Rust that hides an active VPN interface from
selected Android apps by hooking libc `ioctl` at the PLT level.

Companion to the [Kotlin LSPosed module `vpnhide`](https://github.com/okhsunrog/vpnhide),
which covers Java-level VPN detection. This module handles the **native**
detection path — apps calling `ioctl(SIOCGIFNAME)`/`ioctl(SIOCGIFFLAGS)`,
`getifaddrs()`, or raw netlink sockets directly from C/C++/JNI/Flutter
runtime code that never enters ART.

Scope: apps where you want the VPN hidden are listed one-per-line in
`/data/adb/modules/vpnhide_zygisk/targets.txt`. Every other app sees an
unchanged world.

## Status

v0.1.0 — **ioctl hook only**. Covers `SIOCGIFNAME` and `SIOCGIFFLAGS`,
which is the detection path observed in Шоколадница (the cafe loyalty
app that motivated this module). Planned additions:

- `getifaddrs` / `freeifaddrs` wrappers for apps using the higher-level
  libc helper (Dart VM's `NetworkInterface.list()` uses this)
- `ioctl(SIOCGIFCONF)` bulk query filter
- `recvmsg` filter on `NETLINK_ROUTE` sockets for apps that speak netlink
  directly without going through `getifaddrs`

## How it works

The module runs inside each forked app process via NeoZygisk. At
`preAppSpecialize` it reads the package name (`args.nice_name`), checks
`targets.txt`, and either bails out (with `DlCloseModuleLibrary` to
unload itself from memory) or flags itself as active. At
`postAppSpecialize` — once the app's native libraries have been loaded
— it parses `/proc/self/maps`, collects every unique ELF backing an
executable mapping, and calls `pltHookRegister` once per library to
redirect `ioctl` to its replacement function. Finally `pltHookCommit`
applies the patches.

The replacement filter:

- **`SIOCGIFFLAGS`** (app already has a name, wants flags): if the input
  `ifr_name` matches a VPN prefix, set `errno=ENODEV` and return `-1`
  without touching the real ioctl. The kernel never tells the app that
  `tun0` has `IFF_POINTOPOINT` and `IFF_RUNNING`.
- **`SIOCGIFNAME`** (app has an index, wants the name): call the real
  ioctl, check the returned name. If it's a VPN, rewrite to errno=ENODEV
  return -1. The app sees an empty slot at that index and moves on.
- Any other `ioctl` request passes through unchanged.

VPN interface prefixes: `tun`, `ppp`, `tap`, `wg`, `ipsec`, `xfrm`,
`utun`, `l2tp`, `gre`, plus anything containing the substring `vpn`.
Matches the list in the Kotlin companion module.

## Build

Requirements:

- Rust nightly or stable ≥ 1.85 (edition 2024)
- `rustup target add aarch64-linux-android`
- `cargo install cargo-ndk`
- Android NDK installed somewhere under `~/Android/Sdk/ndk/` (auto-detected
  by `build-zip.sh`)

Build & package:

```bash
./build-zip.sh
# Output: target/vpnhide-zygisk.zip (~160 KB)
```

## Install

1. `adb push target/vpnhide-zygisk.zip /sdcard/Download/`
2. Open KernelSU-Next manager → Modules → Install from storage → pick the zip
3. Reboot
4. Edit `/data/adb/modules/vpnhide_zygisk/targets.txt` to add your target
   apps (one package name per line, `#` for comments):

   ```
   ru.plazius.shokoladnica
   com.example.targetapp
   ```

5. Force-stop the target app(s) so they re-fork with the hooks active:
   `adb shell "am force-stop <pkg>"`
6. Verify via `adb logcat | grep vpnhide-zygisk`. Expected lines:
   ```
   I vpnhide-zygisk: pre_app_specialize: targeting ru.plazius.shokoladnica
   I vpnhide-zygisk: hooks installed across 87 libraries
   ```

## Testing

The only reliable way to test is with the original detection being
triggered. For the Шоколадница case: open the app, see that the
"VPN detected" warning no longer appears. For a generic test, install
the `strace` binary from `~/code/android-tools/strace-arm64-android/`
and verify that `SIOCGIFNAME`/`SIOCGIFFLAGS` ioctls targeting VPN
interfaces return `-1 ENODEV` in the traced output.

## Uninstall

1. KernelSU-Next manager → Modules → VPN Hide (Zygisk native) → Remove
2. Reboot

## Files

- `src/lib.rs` — module entry point, scope file handling, hook installer
- `src/hooks.rs` — the `hooked_ioctl` replacement function + errno helper
- `src/filter.rs` — VPN interface name matching logic (unit tested)
- `src/maps.rs` — `/proc/self/maps` parser (unit tested)
- `module/` — KernelSU/Magisk module metadata files
- `build-zip.sh` — cross-compile + package script

## Architecture notes

Zygisk's `pltHookRegister(dev, inode, symbol, new, &old)` patches the PLT
table of **the caller library identified by (dev, inode)**. To intercept
`ioctl` from every possible caller in a process, we have to register a
hook once per unique library that's mapped into the process. That's why
`install_hooks` iterates `/proc/self/maps` and calls `pltHookRegister`
for every distinct ELF. This catches all libraries loaded at
`postAppSpecialize` time; libraries loaded later via `dlopen` would need
a second pass (future work).

## License

0BSD — do whatever you want with it, no warranty.
