/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Run-local SysV shared memory; no host SysV IPC namespace is used.
//!
//! The registry owns supervisor memfds, never guest descriptor numbers. KVM
//! imports those files directly; native ptrace transfers them over a temporary
//! socketpair while guest execution is serialized, then closes every transport
//! descriptor before resuming. Both use the same attachment leases, virtual
//! identifiers, metadata, resource caps, and shared-futex object identity.
//! Unsupported executors fail closed before creating a segment.
// TODO-HUMAN-REVIEW(pending-local-review): new syscall determinization; no PR assigned.

use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use parking_lot::Mutex;
use reverie::Error;
use reverie::Guest;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie::syscalls::{self};

use crate::Detcore;
use crate::RecordOrReplay;
use crate::types::SharedMemoryObjectId;

const PAGE: usize = 4096;
// Explicit, run-local resource limits, not host sysctls.
const MAX_SEGMENTS: usize = 4096;
const MAX_BYTES: usize = 1 << 30;
const SHM_DEST: u32 = 0o1000;
const DS_SIZE: usize = 112; // Linux x86-64 shmid64_ds, including zeroed reserved fields.

#[derive(Clone, Copy, Debug)]
struct Credentials {
    uid: u32,
    gid: u32,
}

#[derive(Debug)]
struct Segment {
    key: i32,
    size: usize,
    length: usize,
    file: File,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    cpid: i32,
    lpid: i32,
    atime: i64,
    dtime: i64,
    ctime: i64,
    attachments: u64,
    reservations: u64,
    removed: bool,
}

impl Segment {
    fn access(&self, who: Credentials, requested: u32) -> Result<(), Errno> {
        if who.uid == 0 {
            return Ok(());
        }
        let shift = if who.uid == self.uid || who.uid == self.cuid {
            6
        } else if who.gid == self.gid || who.gid == self.cgid {
            3
        } else {
            0
        };
        if requested & !(self.mode >> shift) & 7 != 0 {
            Err(Errno::EACCES)
        } else {
            Ok(())
        }
    }

    fn owner(&self, who: Credentials) -> Result<(), Errno> {
        if who.uid == 0 || who.uid == self.uid || who.uid == self.cuid {
            Ok(())
        } else {
            Err(Errno::EPERM)
        }
    }

    fn stat(&self) -> [u8; DS_SIZE] {
        let mut bytes = [0; DS_SIZE];
        for (offset, value) in [
            (0, self.key as u32),
            (4, self.uid),
            (8, self.gid),
            (12, self.cuid),
            (16, self.cgid),
            (20, self.mode | if self.removed { SHM_DEST } else { 0 }),
            (80, self.cpid as u32),
            (84, self.lpid as u32),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        for (offset, value) in [
            (48, self.size as u64),
            (56, self.atime as u64),
            (64, self.dtime as u64),
            (72, self.ctime as u64),
            (88, self.attachments),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
        bytes
    }
}

#[derive(Debug, Default)]
pub(crate) struct Registry {
    next_id: i32,
    segments: BTreeMap<i32, Segment>,
    keys: BTreeMap<i32, i32>,
    bytes: usize,
}

fn io_errno(error: std::io::Error) -> Errno {
    Errno::new(error.raw_os_error().unwrap_or(libc::EIO))
}

impl Registry {
    fn get(
        &mut self,
        key: i32,
        size: usize,
        flags: i32,
        who: Credentials,
        pid: i32,
        now: i64,
    ) -> Result<i32, Errno> {
        if flags & !(0o777 | libc::IPC_CREAT | libc::IPC_EXCL) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if key != libc::IPC_PRIVATE {
            if let Some(&id) = self.keys.get(&key) {
                if flags & (libc::IPC_CREAT | libc::IPC_EXCL) == libc::IPC_CREAT | libc::IPC_EXCL {
                    return Err(Errno::EEXIST);
                }
                let segment = &self.segments[&id];
                if size > segment.size {
                    return Err(Errno::EINVAL);
                }
                let requested = ((flags as u32 >> 6) | (flags as u32 >> 3) | flags as u32) & 7;
                segment.access(who, requested)?;
                return Ok(id);
            }
            if flags & libc::IPC_CREAT == 0 {
                return Err(Errno::ENOENT);
            }
        }
        let length = size
            .checked_add(PAGE - 1)
            .map(|n| n & !(PAGE - 1))
            .filter(|&n| n != 0 && n <= MAX_BYTES)
            .ok_or(Errno::EINVAL)?;
        if self.segments.len() >= MAX_SEGMENTS || self.bytes > MAX_BYTES - length {
            return Err(Errno::ENOSPC);
        }
        let id = self.next_id.checked_add(1).ok_or(Errno::ENOSPC)?;
        // Empty anonymous name; this descriptor is never installed in the guest.
        let raw = unsafe { libc::memfd_create(c"".as_ptr(), libc::MFD_CLOEXEC) };
        if raw < 0 {
            return Err(io_errno(std::io::Error::last_os_error()));
        }
        // SAFETY: memfd_create returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(raw) };
        file.set_len(length as u64).map_err(io_errno)?;
        self.segments.insert(
            id,
            Segment {
                key,
                size,
                length,
                file,
                uid: who.uid,
                gid: who.gid,
                cuid: who.uid,
                cgid: who.gid,
                mode: flags as u32 & 0o777,
                cpid: pid,
                lpid: 0,
                atime: 0,
                dtime: 0,
                ctime: now,
                attachments: 0,
                reservations: 0,
                removed: false,
            },
        );
        if key != libc::IPC_PRIVATE {
            self.keys.insert(key, id);
        }
        self.bytes += length;
        self.next_id = id;
        Ok(id)
    }

    fn collect(&mut self, id: i32) {
        if self
            .segments
            .get(&id)
            .is_some_and(|s| s.removed && s.attachments == 0 && s.reservations == 0)
        {
            self.bytes -= self.segments.remove(&id).unwrap().length;
        }
    }

    fn remove(&mut self, id: i32, who: Credentials) -> Result<(), Errno> {
        let segment = self.segments.get_mut(&id).ok_or(Errno::EINVAL)?;
        segment.owner(who)?;
        if !segment.removed {
            if segment.key != libc::IPC_PRIVATE {
                self.keys.remove(&segment.key);
            }
            segment.key = libc::IPC_PRIVATE;
            segment.removed = true;
        }
        self.collect(id);
        Ok(())
    }

    fn set(
        &mut self,
        id: i32,
        who: Credentials,
        bytes: [u8; DS_SIZE],
        now: i64,
    ) -> Result<(), Errno> {
        let segment = self.segments.get_mut(&id).ok_or(Errno::EINVAL)?;
        segment.owner(who)?;
        let word = |offset| u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let (uid, gid, mode) = (word(4), word(8), word(20));
        if uid == u32::MAX || gid == u32::MAX {
            return Err(Errno::EINVAL);
        }
        if who.uid != 0
            && (uid != segment.uid && uid != who.uid || gid != segment.gid && gid != who.gid)
        {
            return Err(Errno::EPERM);
        }
        segment.uid = uid;
        segment.gid = gid;
        segment.mode = mode & 0o777;
        segment.ctime = now;
        Ok(())
    }
}

/// One real attachment, shared by threads (and harmless metadata snapshots).
/// Only `fork` creates a second attachment. The last mm owner releases it even
/// when a backend cancels an exec/exit future instead of returning from it.
#[derive(Debug)]
pub(crate) struct Attachment {
    registry: Arc<Mutex<Registry>>,
    id: i32,
    pub(crate) length: usize,
    context: Mutex<(i32, i64)>,
    committed: bool,
}

impl Attachment {
    fn reserve(
        registry: Arc<Mutex<Registry>>,
        id: i32,
        who: Credentials,
        readonly: bool,
        pid: i32,
        now: i64,
    ) -> Result<(Self, OwnedFd), Errno> {
        let mut state = registry.lock();
        let segment = state.segments.get_mut(&id).ok_or(Errno::EINVAL)?;
        segment.access(who, if readonly { 4 } else { 6 })?;
        let fd = segment.file.try_clone().map_err(io_errno)?.into();
        let length = segment.length;
        segment.reservations += 1;
        drop(state);
        Ok((
            Self {
                registry,
                id,
                length,
                context: Mutex::new((pid, now)),
                committed: false,
            },
            fd,
        ))
    }

    fn commit(mut self) -> Arc<Self> {
        let (pid, now) = *self.context.get_mut();
        {
            let mut state = self.registry.lock();
            let segment = state.segments.get_mut(&self.id).unwrap();
            segment.reservations -= 1;
            segment.attachments += 1;
            segment.atime = now;
            segment.lpid = pid;
        }
        self.committed = true;
        Arc::new(self)
    }

    pub(crate) fn fork(&self, pid: i32, now: i64) -> Arc<Self> {
        let mut state = self.registry.lock();
        let segment = state.segments.get_mut(&self.id).unwrap();
        segment.attachments += 1;
        segment.atime = now;
        segment.lpid = pid;
        Arc::new(Self {
            registry: Arc::clone(&self.registry),
            id: self.id,
            length: self.length,
            context: Mutex::new((pid, now)),
            committed: true,
        })
    }

    pub(crate) fn context(&self, pid: i32, now: i64) {
        *self.context.lock() = (pid, now);
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        let mut state = self.registry.lock();
        let segment = state.segments.get_mut(&self.id).unwrap();
        if self.committed {
            segment.attachments -= 1;
            let (pid, now) = *self.context.get_mut();
            segment.lpid = pid;
            segment.dtime = now;
        } else {
            segment.reservations -= 1;
        }
        state.collect(self.id);
    }
}

/// Reject operations whose VMA splitting/replacement is not yet modeled for
/// SysV attachments, before they can change either the bytes or the accounting.
pub(crate) fn changes_attachment(
    call: Syscall,
    attachments: &BTreeMap<usize, Arc<Attachment>>,
) -> bool {
    let (number, args) = call.into_parts();
    let overlaps = |address: usize, length: usize| {
        let length = length.saturating_add(PAGE - 1) & !(PAGE - 1);
        attachments.iter().any(|(&start, attachment)| {
            address < start.saturating_add(attachment.length)
                && start < address.saturating_add(length)
        })
    };
    match number {
        Sysno::munmap | Sysno::madvise => overlaps(args.arg0 as usize, args.arg1 as usize),
        Sysno::mmap if args.arg3 as i32 & libc::MAP_FIXED != 0 => {
            overlaps(args.arg0 as usize, args.arg1 as usize)
        }
        Sysno::mremap => {
            overlaps(args.arg0 as usize, (args.arg1 as usize).max(1))
                || (args.arg3 as i32 & libc::MREMAP_FIXED != 0
                    && overlaps(args.arg4 as usize, args.arg2 as usize))
        }
        // DONTFORK/WIPEONFORK would otherwise make the metadata's inherited view false.
        _ => false,
    }
}

impl<T: RecordOrReplay> Detcore<T> {
    pub(crate) async fn handle_sysv_shm<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        if !guest.supports_shared_backing() {
            return Err(Errno::ENOSYS.into());
        }
        let registry = Arc::clone(&guest.local_state().ok_or(Errno::ENOSYS)?.sysv_shm);
        let who = Credentials {
            uid: self.cfg.virtual_uid,
            gid: self.cfg.virtual_gid,
        };
        let pid = guest.thread_state().detpid.unwrap_or(self.detpid).as_raw();
        let now = super::time::guest_clock_time(guest).await.as_secs() as i64;
        let (number, args) = call.into_parts();
        let id = args.arg0 as i32;
        match number {
            Sysno::shmget => {
                Ok(registry
                    .lock()
                    .get(id, args.arg1 as usize, args.arg2 as i32, who, pid, now)?
                    as i64)
            }
            Sysno::shmat => {
                let flags = args.arg2 as i32;
                // No pretend support for executable, remapping, huge or no-reserve attachments.
                if flags & !(libc::SHM_RDONLY | libc::SHM_RND) != 0 {
                    return Err(Errno::EOPNOTSUPP.into());
                }
                let mut address = args.arg1 as usize;
                if flags & libc::SHM_RND != 0 {
                    address &= !(PAGE - 1);
                }
                if address % PAGE != 0 || (args.arg1 != 0 && address == 0) {
                    return Err(Errno::EINVAL.into());
                }
                let (attachment, fd) = Attachment::reserve(
                    registry,
                    id,
                    who,
                    flags & libc::SHM_RDONLY != 0,
                    pid,
                    now,
                )?;
                let prot = libc::PROT_READ
                    | if flags & libc::SHM_RDONLY == 0 {
                        libc::PROT_WRITE
                    } else {
                        0
                    };
                let map_flags = libc::MAP_SHARED
                    | if address != 0 {
                        libc::MAP_FIXED_NOREPLACE
                    } else {
                        0
                    };
                let result = guest
                    .map_shared_backing(
                        fd,
                        (address != 0).then_some(address as u64),
                        attachment.length,
                        prot,
                        map_flags,
                    )
                    .await;
                let mapped = match result {
                    Err(Error::Errno(Errno::EEXIST)) => return Err(Errno::EINVAL.into()),
                    other => other?,
                } as usize;
                let attachment = attachment.commit();
                let mut memory = guest
                    .thread_state()
                    .memory_metadata
                    .lock()
                    .expect("memory metadata mutex poisoned");
                memory.map_object(
                    mapped,
                    attachment.length,
                    SharedMemoryObjectId::SysV { id: id as u32 },
                    0,
                );
                assert!(memory.sysv_attachments.insert(mapped, attachment).is_none());
                Ok(mapped as i64)
            }
            Sysno::shmdt => {
                let address = args.arg0 as usize;
                let length = guest
                    .thread_state()
                    .memory_metadata
                    .lock()
                    .expect("memory metadata mutex poisoned")
                    .sysv_attachments
                    .get(&address)
                    .ok_or(Errno::EINVAL)?
                    .length;
                guest
                    .inject_with_retry(Syscall::Munmap(
                        syscalls::Munmap::new()
                            .with_addr(Addr::from_raw(address))
                            .with_len(length),
                    ))
                    .await?;
                let mut memory = guest
                    .thread_state()
                    .memory_metadata
                    .lock()
                    .expect("memory metadata mutex poisoned");
                let attachment = memory.sysv_attachments.remove(&address).unwrap();
                attachment.context(pid, now);
                memory.unmap(address, length);
                drop(attachment);
                Ok(0)
            }
            Sysno::shmctl => {
                match args.arg1 as i32 {
                    libc::IPC_STAT => {
                        let bytes = {
                            let state = registry.lock();
                            let segment = state.segments.get(&id).ok_or(Errno::EINVAL)?;
                            segment.access(who, 4)?;
                            segment.stat()
                        };
                        let address = AddrMut::<[u8; DS_SIZE]>::from_raw(args.arg2 as usize)
                            .ok_or(Errno::EFAULT)?;
                        guest.memory().write_value(address, &bytes)?;
                    }
                    libc::IPC_SET => {
                        // Check ownership before inspecting the user's pointer, like Linux.
                        registry
                            .lock()
                            .segments
                            .get(&id)
                            .ok_or(Errno::EINVAL)?
                            .owner(who)?;
                        let address = Addr::<[u8; DS_SIZE]>::from_raw(args.arg2 as usize)
                            .ok_or(Errno::EFAULT)?;
                        let bytes = guest.memory().read_value(address)?;
                        registry.lock().set(id, who, bytes, now)?;
                    }
                    libc::IPC_RMID => registry.lock().remove(id, who)?,
                    // SHM_LOCK/UNLOCK, SHM_STAT/INFO and IPC_INFO are not emulated.
                    _ => return Err(Errno::EOPNOTSUPP.into()),
                }
                Ok(0)
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const OWNER: Credentials = Credentials { uid: 42, gid: 7 };

    #[test]
    fn key_permissions_sizes_and_monotonic_ids() {
        let mut state = Registry::default();
        assert_eq!(state.get(1, 1, 0, OWNER, 11, 100), Err(Errno::ENOENT));
        assert_eq!(
            state.get(1, 0, libc::IPC_CREAT, OWNER, 11, 100),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            state.get(1, usize::MAX, libc::IPC_CREAT, OWNER, 11, 100),
            Err(Errno::EINVAL)
        );
        let id = state
            .get(1, 56, libc::IPC_CREAT | 0o640, OWNER, 11, 100)
            .unwrap();
        assert_eq!(state.get(1, 0, 0o600, OWNER, 11, 101), Ok(id));
        assert_eq!(state.get(1, 57, 0, OWNER, 11, 101), Err(Errno::EINVAL));
        assert_eq!(
            state.get(1, 56, libc::IPC_CREAT | libc::IPC_EXCL, OWNER, 11, 101),
            Err(Errno::EEXIST)
        );
        let group = Credentials { uid: 43, gid: 7 };
        assert_eq!(state.get(1, 0, 0o400, group, 12, 101), Ok(id));
        assert_eq!(state.get(1, 0, 0o200, group, 12, 101), Err(Errno::EACCES));
        assert_eq!(state.remove(id, group), Err(Errno::EPERM));
        let mut update = state.segments[&id].stat();
        update[4..8].copy_from_slice(&43u32.to_ne_bytes());
        assert_eq!(state.set(id, OWNER, update, 102), Err(Errno::EPERM));
        update[4..8].copy_from_slice(&42u32.to_ne_bytes());
        update[20..24].copy_from_slice(&0o600u32.to_ne_bytes());
        state.set(id, OWNER, update, 103).unwrap();
        assert_eq!(state.get(1, 0, 0o400, group, 12, 103), Err(Errno::EACCES));
        state.remove(id, OWNER).unwrap();
        assert!(state.get(1, 56, libc::IPC_CREAT, OWNER, 11, 104).unwrap() > id);
    }

    #[test]
    fn reservations_fork_snapshots_and_deferred_removal() {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let id = registry
            .lock()
            .get(9, 56, libc::IPC_CREAT | 0o600, OWNER, 11, 100)
            .unwrap();
        let (pending, fd) =
            Attachment::reserve(Arc::clone(&registry), id, OWNER, false, 11, 101).unwrap();
        drop(fd);
        drop(pending); // failed mapping must not count as attach or detach
        assert_eq!(registry.lock().segments[&id].attachments, 0);
        assert_eq!(registry.lock().segments[&id].dtime, 0);
        let (pending, fd) =
            Attachment::reserve(Arc::clone(&registry), id, OWNER, false, 11, 102).unwrap();
        drop(fd);
        let parent = pending.commit();
        let snapshot = Arc::clone(&parent);
        assert_eq!(registry.lock().segments[&id].attachments, 1);
        let child = parent.fork(12, 103);
        assert_eq!(registry.lock().segments[&id].attachments, 2);
        registry.lock().remove(id, OWNER).unwrap();
        let replacement = registry
            .lock()
            .get(9, 56, libc::IPC_CREAT, OWNER, 11, 104)
            .unwrap();
        assert_ne!(id, replacement);
        drop(child); // child exec/exit releases its independent mm
        assert_eq!(registry.lock().segments[&id].attachments, 1);
        drop(snapshot);
        drop(parent);
        assert!(!registry.lock().segments.contains_key(&id));
        assert!(registry.lock().segments.contains_key(&replacement));
    }

    #[test]
    fn metadata_snapshots_threads_and_real_forks_have_distinct_lifetimes() {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let id = registry.lock().get(0, 56, 0o600, OWNER, 11, 100).unwrap();
        let (pending, fd) =
            Attachment::reserve(Arc::clone(&registry), id, OWNER, false, 11, 101).unwrap();
        drop(fd);
        let mut memory = crate::memory::MemoryMetadata::new();
        memory.sysv_attachments.insert(0x1000, pending.commit());
        let snapshot = memory.clone();
        assert_eq!(registry.lock().segments[&id].attachments, 1);
        let child = memory.fork(12, 102);
        assert_eq!(registry.lock().segments[&id].attachments, 2);
        drop(child);
        assert_eq!(registry.lock().segments[&id].attachments, 1);
        let thread = Arc::new(memory);
        let sibling = Arc::clone(&thread);
        drop(thread);
        assert_eq!(registry.lock().segments[&id].attachments, 1);
        drop(snapshot); // a failed exec's rollback snapshot never attached
        sibling.sysv_context(11, 103);
        drop(sibling);
        assert_eq!(registry.lock().segments[&id].attachments, 0);
        assert_eq!(registry.lock().segments[&id].dtime, 103);
    }

    #[test]
    fn stat_abi_and_capacity_are_explicit() {
        assert_eq!(std::mem::size_of::<libc::shmid_ds>(), DS_SIZE);
        assert_eq!(std::mem::offset_of!(libc::shmid_ds, shm_segsz), 48);
        assert_eq!(std::mem::offset_of!(libc::shmid_ds, shm_nattch), 88);
        let mut state = Registry::default();
        let id = state.get(0, 56, 0o600, OWNER, 11, 100).unwrap();
        let bytes = state.segments[&id].stat();
        assert_eq!(
            u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
            OWNER.uid
        );
        assert_eq!(u64::from_ne_bytes(bytes[48..56].try_into().unwrap()), 56);
        assert!(bytes[24..48].iter().all(|&byte| byte == 0));
        assert!(bytes[96..112].iter().all(|&byte| byte == 0));
        state.bytes = MAX_BYTES;
        assert_eq!(state.get(0, 1, 0o600, OWNER, 11, 100), Err(Errno::ENOSPC));
        state.bytes = PAGE;
        state.next_id = i32::MAX;
        assert_eq!(state.get(0, 1, 0o600, OWNER, 11, 100), Err(Errno::ENOSPC));
    }
}
