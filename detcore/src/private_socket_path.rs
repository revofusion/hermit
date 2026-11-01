//! Physical pathname authority for synchronous native Unix socket producers.
//!
//! Callers must hold the serialized physical-attempt turn through these probes
//! and the original injection: no scheduler grant may intervene. Injected calls
//! bypass Detcore's virtual stat/statx identities. This is the ordinary fully
//! traced application boundary, not protection against a malicious host/root or
//! an untraced process mutating guest memory or the private directory. Namespace,
//! asynchronous producer and descriptor-export operations revoke the capability
//! before execution in the event-driven policy.

use std::os::unix::ffi::OsStrExt;

use reverie::Guest;
use reverie::syscalls::{self, Addr, AddrMut, MemoryAccess, PathPtr, ReadAddr, Syscall, SyscallInfo, Sysno};

use crate::Detcore;
use crate::config::EventDrivenPrivateTmp;
use crate::record_or_replay::RecordOrReplay;

const PAGE_LEN: usize = 8192;
const HOW: usize = 4096;
const STAT: usize = 4160;
const EMPTY: usize = 4480;
const PRIVATE_RESOLVE: u64 =
    libc::RESOLVE_BENEATH | libc::RESOLVE_NO_XDEV | libc::RESOLVE_NO_SYMLINKS;
const STATX_MNT_ID: u32 = 0x1000;

fn raw(number: Sysno, args: [usize; 6]) -> Syscall {
    Syscall::from_raw(number, syscalls::SyscallArgs::new(args[0], args[1], args[2], args[3], args[4], args[5]))
}

/// No normalization: the spelling that Linux will consume must itself be exact.
fn canonical_absolute(path: &[u8]) -> bool {
    path.len() > 1
        && path[0] == b'/'
        && !path.contains(&0)
        && path[1..].split(|byte| *byte == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}

fn private_relative(path: &[u8]) -> Option<&[u8]> {
    canonical_absolute(path).then_some(())?;
    path.strip_prefix(b"/tmp/")
}

#[derive(Debug, PartialEq, Eq)]
enum UnixAddress<'a> {
    Abstract,
    Path(&'a [u8]),
}

fn unix_address(bytes: &[u8]) -> Option<UnixAddress<'_>> {
    if bytes.len() < 3 || bytes.len() > std::mem::size_of::<libc::sockaddr_un>()
        || u16::from_ne_bytes(bytes[..2].try_into().ok()?) != libc::AF_UNIX as u16
    {
        return None;
    }
    if bytes[2] == 0 {
        return Some(UnixAddress::Abstract);
    }
    let supplied = &bytes[2..];
    // Refuse unterminated and noncanonical names, rather than guess Linux's
    // implicit terminator rules for a full sun_path array.
    let end = supplied.iter().position(|byte| *byte == 0)?;
    let path = &supplied[..end];
    private_relative(path)?;
    Some(UnixAddress::Path(path))
}

struct Probe {
    page: usize,
}

impl Probe {
    async fn new<G: Guest<Detcore<T>>, T: RecordOrReplay>(guest: &mut G) -> Option<Self> {
        let page = guest.inject_with_retry(raw(Sysno::mmap, [
            0, PAGE_LEN, (libc::PROT_READ | libc::PROT_WRITE) as usize,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize, usize::MAX, 0,
        ])).await.ok()? as usize;
        (page != 0).then_some(Self { page })
    }

    async fn finish<G: Guest<Detcore<T>>, T: RecordOrReplay>(self, guest: &mut G) -> bool {
        guest.inject_with_retry(raw(Sysno::munmap, [self.page, PAGE_LEN, 0, 0, 0, 0])).await.is_ok()
    }

    fn put<G: Guest<Detcore<T>>, T: RecordOrReplay>(&self, guest: &mut G, offset: usize, bytes: &[u8]) -> Option<()> {
        guest.memory().write_exact(AddrMut::<u8>::from_raw(self.page + offset)?, bytes).ok()
    }

    fn path<G: Guest<Detcore<T>>, T: RecordOrReplay>(&self, guest: &mut G, path: &[u8]) -> Option<()> {
        if path.len() >= HOW || path.contains(&0) {
            return None;
        }
        self.put(guest, 0, path)?;
        self.put(guest, path.len(), &[0])
    }

    async fn open<G: Guest<Detcore<T>>, T: RecordOrReplay>(
        &self, guest: &mut G, dirfd: i32, path: &[u8], directory: bool, resolve: u64,
    ) -> Option<i32> {
        self.path(guest, path)?;
        let flags = libc::O_PATH | libc::O_CLOEXEC | if directory { libc::O_DIRECTORY } else { 0 };
        let mut how = [0u8; 24];
        how[..8].copy_from_slice(&(flags as u64).to_ne_bytes());
        how[16..].copy_from_slice(&resolve.to_ne_bytes());
        self.put(guest, HOW, &how)?;
        guest.inject_with_retry(raw(Sysno::openat2, [dirfd as usize, self.page, self.page + HOW, how.len(), 0, 0]))
            .await.ok().and_then(|fd| i32::try_from(fd).ok())
    }

    async fn stat<G: Guest<Detcore<T>>, T: RecordOrReplay>(&self, guest: &mut G, fd: i32) -> Option<libc::stat> {
        guest.inject_with_retry(raw(Sysno::fstat, [fd as usize, self.page + STAT, 0, 0, 0, 0])).await.ok()?;
        guest.memory().read_value(Addr::<libc::stat>::from_raw(self.page + STAT)?).ok()
    }

    async fn root<G: Guest<Detcore<T>>, T: RecordOrReplay>(
        &self, guest: &mut G, receipt: EventDrivenPrivateTmp,
    ) -> Option<i32> {
        // Crossing the /tmp bind is intentional here. Descendant lookup below
        // this authenticated anchor additionally requires NO_XDEV.
        let fd = self.open(guest, libc::AT_FDCWD, b"/tmp", true, libc::RESOLVE_NO_SYMLINKS).await?;
        let valid = async {
            let stat = self.stat(guest, fd).await?;
            if stat.st_dev != receipt.device || stat.st_ino != receipt.inode
                || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            {
                return None;
            }
            self.put(guest, EMPTY, &[0])?;
            guest.inject_with_retry(raw(Sysno::statx, [
                fd as usize, self.page + EMPTY, libc::AT_EMPTY_PATH as usize,
                STATX_MNT_ID as usize, self.page + STAT, 0,
            ])).await.ok()?;
            let stat: syscalls::linux_abi::Statx = guest.memory()
                .read_value(Addr::from_raw(self.page + STAT)?).ok()?;
            (stat.stx_mask & STATX_MNT_ID != 0 && stat.stx_mnt_id == receipt.raw_mount_id).then_some(())
        }.await.is_some();
        if valid {
            Some(fd)
        } else {
            close(guest, fd).await;
            None
        }
    }

    async fn private_path<G: Guest<Detcore<T>>, T: RecordOrReplay>(
        &self, guest: &mut G, root: i32, path: &[u8], connect: bool,
    ) -> bool {
        let Some(relative) = private_relative(path) else { return false; };
        // Bind's leaf need not exist. Prove its exact parent, not merely the
        // pathname's textual prefix or the filesystem's device number.
        let parent = relative.iter().rposition(|byte| *byte == b'/')
            .map_or(b".".as_slice(), |end| &relative[..end]);
        let Some(fd) = self.open(guest, root, parent, true, PRIVATE_RESOLVE).await else { return false; };
        if !close(guest, fd).await { return false; }
        if !connect { return true; }
        // Connect follows the final component too: reject a final symlink or
        // a bind mount over that component, not just symlinks in its parent.
        let Some(fd) = self.open(guest, root, relative, false, PRIVATE_RESOLVE).await else { return false; };
        let socket = self.stat(guest, fd).await
            .is_some_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFSOCK);
        close(guest, fd).await && socket
    }

    async fn regular<G: Guest<Detcore<T>>, T: RecordOrReplay>(
        &self, guest: &mut G, dirfd: i32, path: usize, flags: i32,
    ) -> bool {
        // A regular source cannot carry a live Unix socket out of its private
        // directory. Preserve relative ordinary PG WAL/data renames as well.
        if guest.inject_with_retry(raw(Sysno::newfstatat, [
            dirfd as usize, path, self.page + STAT, flags as usize, 0, 0,
        ])).await.is_err() {
            return false;
        }
        guest.memory().read_value(Addr::<libc::stat>::from_raw(self.page + STAT).unwrap())
            .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFREG)
    }
}

async fn close<G: Guest<Detcore<T>>, T: RecordOrReplay>(guest: &mut G, fd: i32) -> bool {
    guest.inject_with_retry(raw(Sysno::close, [fd as usize, 0, 0, 0, 0, 0])).await.is_ok()
}

/// A regular file reached through the authenticated private /tmp mount.
/// Mount identity is essential: a pathname prefix alone admits bind-mounted
/// or imported files. Linux rejects rename/link across this mount boundary.
pub(crate) async fn flock_file_owned<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    pin: &reverie::PinnedFlock,
) -> Option<(u64, u64)> {
    let receipt = guest.config().event_driven_private_tmp?;
    let facts = pin.facts();
    let &(device, inode, mode) = facts.identity.as_ref().ok()?;
    if mode & libc::S_IFMT != libc::S_IFREG
        || facts.mount_id.as_ref().ok().copied() != Some(receipt.raw_mount_id)
        || device != receipt.device
    {
        return None;
    }
    // tmpfs, ext, btrfs, XFS and ZFS have local Linux flock semantics.
    // Network lock managers have producers outside this guest's scheduler.
    if !matches!(facts.filesystem.as_ref().ok()?,
        0x0102_1994 | 0xEF53 | 0x9123_683E | 0x5846_5342 | 0x2FC1_2FC1)
    {
        return None;
    }
    let probe = Probe::new(guest).await?;
    let owned = match probe.root(guest, receipt).await {
        Some(root) => close(guest, root).await,
        None => false,
    };
    (probe.finish(guest).await && owned).then_some((device, inode))
}

/// Must immediately precede the original Bind/Connect in its physical turn.
/// Probe failure only withdraws authority; it never substitutes the guest errno.
pub(crate) async fn address_owned<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G, call: Syscall,
) -> bool {
    if !guest.config().event_driven_io { return false; }
    let (number, args) = call.into_parts();
    if !matches!(number, Sysno::bind | Sysno::connect) { return false; }
    let length = args.arg2 as usize;
    let mut bytes = [0u8; std::mem::size_of::<libc::sockaddr_un>()];
    if length > bytes.len() { return false; }
    let Some(address) = Addr::<u8>::from_raw(args.arg1 as usize) else { return false; };
    if guest.memory().read_exact(address, &mut bytes[..length]).is_err() { return false; }
    let path = match unix_address(&bytes[..length]) {
        // Admission gives a fresh isolated local-network namespace. No private
        // filesystem receipt is needed for this distinct kernel namespace.
        Some(UnixAddress::Abstract) => return true,
        Some(UnixAddress::Path(path)) => path,
        None => return false,
    };
    let Some(receipt) = guest.config().event_driven_private_tmp else { return false; };
    let Some(probe) = Probe::new(guest).await else { return false; };
    let owned = match probe.root(guest, receipt).await {
        Some(root) => {
            let owned = probe.private_path(guest, root, path, number == Sysno::connect).await;
            close(guest, root).await && owned
        }
        None => false,
    };
    probe.finish(guest).await && owned
}

fn path_bytes<G: Guest<Detcore<T>>, T: RecordOrReplay>(guest: &G, address: usize) -> Option<std::path::PathBuf> {
    PathPtr::from_ptr(address as *const libc::c_char)?.read(&guest.memory()).ok()
}

/// Whether a pathname mutation cannot export an owned Unix socket. Unknown
/// operations/sources withdraw authority before Linux executes the original call.
pub(crate) async fn filesystem_change_safe<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G, call: Syscall,
) -> bool {
    if !guest.config().event_driven_io { return false; }
    let (number, args) = call.into_parts();
    // Removing names and creating empty directories/nodes cannot move an
    // existing endpoint outside its proven root. Later binds reprove the root.
    if matches!(number, Sysno::unlink | Sysno::unlinkat | Sysno::rmdir
        | Sysno::mkdir | Sysno::mkdirat | Sysno::mknod | Sysno::mknodat)
    {
        return true;
    }
    let (old_dir, old, new_dir, new, exchange, stat_flags) = match number {
        Sysno::rename => (libc::AT_FDCWD, args.arg0, libc::AT_FDCWD, args.arg1, false, libc::AT_SYMLINK_NOFOLLOW),
        Sysno::renameat | Sysno::renameat2 => (args.arg0 as i32, args.arg1, args.arg2 as i32, args.arg3,
            number == Sysno::renameat2 && args.arg4 as u32 & libc::RENAME_EXCHANGE != 0, libc::AT_SYMLINK_NOFOLLOW),
        Sysno::link => (libc::AT_FDCWD, args.arg0, libc::AT_FDCWD, args.arg1, false, libc::AT_SYMLINK_NOFOLLOW),
        Sysno::linkat => (args.arg0 as i32, args.arg1, args.arg2 as i32, args.arg3, false,
            (if args.arg4 as i32 & libc::AT_SYMLINK_FOLLOW == 0 { libc::AT_SYMLINK_NOFOLLOW } else { 0 })
                | (args.arg4 as i32 & libc::AT_EMPTY_PATH)),
        // Symlink's target is text, not a renamed source; only a proved private
        // destination is admitted. Future socket lookups reject every symlink.
        Sysno::symlink => (libc::AT_FDCWD, 0, libc::AT_FDCWD, args.arg1, false, 0),
        Sysno::symlinkat => (libc::AT_FDCWD, 0, args.arg1 as i32, args.arg2, false, 0),
        _ => return false,
    };
    let Some(probe) = Probe::new(guest).await else { return false; };
    let regular = old != 0 && probe.regular(guest, old_dir, old as usize, stat_flags).await
        && (!exchange || probe.regular(guest, new_dir, new as usize, libc::AT_SYMLINK_NOFOLLOW).await);
    let safe = if regular {
        true
    } else if let Some(receipt) = guest.config().event_driven_private_tmp {
        match probe.root(guest, receipt).await {
            Some(root) => {
                let mut private = false;
                if let Some(new) = path_bytes(guest, new as usize) {
                    private = probe.private_path(guest, root, new.as_os_str().as_bytes(), false).await;
                    if private && old != 0 {
                        private = if let Some(old) = path_bytes(guest, old as usize) {
                            // For linkat with SYMLINK_FOLLOW a private parent is
                            // insufficient: the referent may be outside. The
                            // regular-source case above is the only exception.
                            let follows = number == Sysno::linkat && args.arg4 as i32 & libc::AT_SYMLINK_FOLLOW != 0;
                            !follows && probe.private_path(guest, root, old.as_os_str().as_bytes(), false).await
                        } else { false };
                    }
                }
                close(guest, root).await && private
            }
            None => false,
        }
    } else {
        false
    };
    probe.finish(guest).await && safe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_names_require_exact_absolute_components() {
        assert_eq!(private_relative(b"/tmp/hermit-fullstack/pg/sock/.s.PGSQL.5432"), Some(b"hermit-fullstack/pg/sock/.s.PGSQL.5432".as_slice()));
        for path in [b"tmp/socket".as_slice(), b"/tmp", b"/tmp/", b"/tmp//socket", b"/tmp/../socket", b"/tmp/./socket", b"/tmp/socket/", b"/tmpx/socket", b"/tmp/socket\0"] {
            assert!(private_relative(path).is_none(), "{path:?}");
        }
    }

    #[test]
    fn unix_names_distinguish_abstract_and_terminated_pathnames() {
        let family = (libc::AF_UNIX as u16).to_ne_bytes();
        let mut bytes = family.to_vec();
        assert_eq!(unix_address(&bytes), None);
        bytes.extend_from_slice(b"\0abstract\0binary");
        assert_eq!(unix_address(&bytes), Some(UnixAddress::Abstract));
        bytes.truncate(2);
        bytes.extend_from_slice(b"/tmp/socket");
        assert_eq!(unix_address(&bytes), None);
        bytes.push(0);
        assert_eq!(unix_address(&bytes), Some(UnixAddress::Path(b"/tmp/socket")));
        bytes[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        assert_eq!(unix_address(&bytes), None);
    }
}
