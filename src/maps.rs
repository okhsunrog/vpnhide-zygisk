//! Parse `/proc/self/maps` to enumerate the unique ELFs loaded into the
//! current process.
//!
//! Used to decide which libraries' PLT tables to patch. Zygisk's
//! `pltHookRegister(dev, inode, symbol, new_fn, old_fn)` patches the PLT of
//! a specific library identified by (dev, inode). To intercept a libc
//! function like `ioctl` from every caller in the process, we have to
//! register the hook once per distinct library.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// An executable mapping in the process's address space corresponding to a
/// real file on disk.
#[derive(Debug, Clone)]
pub struct LoadedElf {
    pub path: PathBuf,
    pub dev: libc::dev_t,
    pub inode: libc::ino_t,
}

/// Read `/proc/self/maps` and return one `LoadedElf` per unique file backing
/// an executable mapping (`r-xp` perms, file path set, non-empty).
///
/// Duplicates caused by multiple mappings of the same file (code, rodata,
/// etc.) are collapsed by `(dev, inode)`. Anonymous mappings, `[vdso]`,
/// `[stack]`, `/dev/ashmem/...` etc. are filtered out because we can't PLT-hook
/// them meaningfully.
pub fn loaded_elfs() -> Vec<LoadedElf> {
    let content = match fs::read_to_string("/proc/self/maps") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    parse_maps(&content)
}

fn parse_maps(content: &str) -> Vec<LoadedElf> {
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut result: Vec<LoadedElf> = Vec::new();

    for line in content.lines() {
        // Format:
        //   address            perms offset   dev    inode    pathname
        //   7f8a1b000-7f8a2b000 r-xp  00000000 fe:00  1234     /apex/.../libc.so
        let Some((path, perms)) = parse_maps_line(line) else {
            continue;
        };
        // Only care about executable mappings — PLT entries live in
        // executable segments.
        if !perms.contains('x') {
            continue;
        }
        // Skip pseudo-files and memory-only mappings.
        if !is_real_file_path(&path) {
            continue;
        }

        // Resolve dev/ino via stat on the real file. The `dev` field in
        // /proc/self/maps is in major:minor hex form which we'd have to
        // combine; stat is simpler and matches what Zygisk's lookup will do.
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        let key = (meta.dev(), meta.ino());
        if seen.insert(key) {
            result.push(LoadedElf {
                path: PathBuf::from(path),
                dev: meta.dev() as libc::dev_t,
                inode: meta.ino() as libc::ino_t,
            });
        }
    }

    result
}

/// Returns `(pathname, perms)` if the line is a file-backed executable or
/// other mapping, otherwise None.
fn parse_maps_line(line: &str) -> Option<(String, String)> {
    // Split at whitespace; last field is the pathname (may contain spaces,
    // though that's rare on Android).
    //
    // Manual tokenising instead of `split_whitespace` because `split_whitespace`
    // loses position info and we need to keep the rest of the line as "path".
    let mut fields = line.splitn(6, ' ').filter(|s| !s.is_empty());
    let _addr = fields.next()?;
    let perms = fields.next()?;
    let _offset = fields.next()?;
    let _dev = fields.next()?;
    let _inode = fields.next()?;
    let path = fields.next()?.trim_start();

    if path.is_empty() {
        return None;
    }
    Some((path.to_string(), perms.to_string()))
}

fn is_real_file_path(path: &str) -> bool {
    if path.starts_with('[') {
        // [vdso], [vvar], [stack], [heap], [anon:...]
        return false;
    }
    if path.starts_with("/dev/ashmem/") || path == "/dev/null" || path.starts_with("/memfd:") {
        return false;
    }
    // Sanity: path must exist (anonymous mappings or deleted files get filtered)
    Path::new(path).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_anonymous_and_pseudo_mappings() {
        assert!(!is_real_file_path("[vdso]"));
        assert!(!is_real_file_path("[heap]"));
        assert!(!is_real_file_path("[stack]"));
        assert!(!is_real_file_path("[anon:dalvik-heap]"));
        assert!(!is_real_file_path("/memfd:xyz"));
        assert!(!is_real_file_path("/dev/ashmem/foo"));
    }

    #[test]
    fn parses_a_typical_line() {
        let line =
            "7cb7a00000-7cb7a19000 r-xp 00000000 fd:03 12345  /apex/com.android.runtime/lib64/bionic/libc.so";
        let (path, perms) = parse_maps_line(line).expect("parse ok");
        assert_eq!(path, "/apex/com.android.runtime/lib64/bionic/libc.so");
        assert_eq!(perms, "r-xp");
    }

    #[test]
    fn rejects_non_executable_mapping_by_caller_filter() {
        // parse_maps_line itself doesn't filter — that's the caller's job.
        // This test documents that the filter on `!perms.contains('x')` must
        // be in `parse_maps()`, not here.
        let line =
            "7cb7a20000-7cb7a30000 r--p 00020000 fd:03 12345  /apex/com.android.runtime/lib64/bionic/libc.so";
        let (_, perms) = parse_maps_line(line).expect("parse ok");
        assert!(!perms.contains('x'));
    }
}
