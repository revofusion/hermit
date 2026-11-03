//! Native file-lock dependencies. The kernel, never this registry, grants locks.
use std::collections::BTreeMap;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use reverie::syscalls::{Errno, Sysno};
use reverie::{Error, Guest, PinnedFlock};

use crate::event_driven_io::{Key, Snapshot, Update};
use crate::fd::DetFd;
use crate::procfs::locks::HeldLock;
use crate::record_or_replay::RecordOrReplay;
use crate::types::OpenFileId;
use crate::Detcore;

#[derive(Debug, Default)]
pub(crate) struct Registry {
    // Live descriptions/waits own a domain. Once they disappear, a recycled
    // native inode must receive a fresh logical key, not inherit its predecessor.
    files: Mutex<BTreeMap<(u64, u64), Weak<Domain>>>,
    pending: Mutex<Vec<Key>>,
    dirty: AtomicBool,
    disabled: AtomicBool,
}

impl Registry {
    pub(crate) fn domain(self: &Arc<Self>, identity: (u64, u64), first: OpenFileId) -> Arc<Domain> {
        let mut files = self.files.lock();
        if let Some(domain) = files.get(&identity).and_then(Weak::upgrade) {
            return domain;
        }
        let domain = Arc::new(Domain {
            key: Key::Flock(first),
            registry: Arc::downgrade(self),
        });
        files.insert(identity, Arc::downgrade(&domain));
        domain
    }

    pub(crate) fn disable(&self) {
        if !self.disabled.swap(true, Ordering::AcqRel) {
            for domain in self.files.lock().values().filter_map(Weak::upgrade) {
                self.changed(domain.key);
            }
        }
    }

    fn changed(&self, key: Key) {
        self.pending.lock().push(key);
        self.dirty.store(true, Ordering::Release);
    }

    pub(crate) fn drain(&self, output: &mut Vec<Key>) -> bool {
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return false;
        }
        output.extend(self.pending.lock().drain(..));
        output.sort_unstable();
        output.dedup();
        !output.is_empty()
    }
}

#[derive(Debug)]
pub(crate) struct Domain {
    pub(crate) key: Key,
    registry: Weak<Registry>,
}

impl Domain {
    pub(crate) fn enabled(&self) -> bool {
        self.registry.upgrade().is_some_and(|registry| !registry.disabled.load(Ordering::Acquire))
    }

    pub(crate) fn changed(&self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.changed(self.key);
        }
    }
}

/// One model description's reference, shared by its dup/fork/SCM aliases.
/// Retiring queued rights must wake waiters even when no fd slot was closed.
#[derive(Debug)]
pub(crate) struct Reference(pub(crate) Arc<Domain>);

impl Drop for Reference {
    fn drop(&mut self) {
        self.0.changed();
    }
}

/// The native syscall's retained OFD, independent of the original fd slot.
#[derive(Debug)]
pub(crate) struct Wait {
    pin: Option<PinnedFlock>,
    description: DetFd,
    domain: Arc<Domain>,
    held_mode: Option<i32>,
}

impl Drop for Wait {
    fn drop(&mut self) {
        // A last pin can release a lock. Publish only after the real fput.
        drop(self.pin.take());
        self.domain.changed();
    }
}

impl Wait {
    pub(crate) async fn prepare<T: RecordOrReplay, G: Guest<Detcore<T>>>(
        guest: &mut G,
        call: reverie::syscalls::Flock,
    ) -> Result<Option<Self>, Error> {
        let config = guest.config();
        if !config.event_driven_io || config.backend != reverie::BackendCapabilities::PTRACE {
            return Ok(None);
        }
        let operation = call.operation();
        let mode = operation & !libc::LOCK_NB;
        if !matches!(mode, libc::LOCK_SH | libc::LOCK_EX | libc::LOCK_UN) {
            return Ok(None);
        }
        let Some(registry) = guest.local_state().and_then(|global| global.flock_waits.clone()) else {
            return Ok(None);
        };
        if registry.disabled.load(Ordering::Acquire) {
            return Ok(None);
        }
        let Ok(description) = guest.thread_state().with_detfd(call.fd(), |fd| fd.clone()) else {
            return Ok(None);
        };
        let existing_domain = description.flock_domain();
        // Live-discovered descriptions can already have external aliases.
        if existing_domain.is_none() && description.known_flock_mode().is_none()
            && !description.flock_mode_may_be_stale()
        {
            return Ok(None);
        }
        let pin = guest.pin_flock(call.fd()).await?;
        let domain = if let Some(domain) = existing_domain {
            domain
        } else {
            let Some(identity) = crate::private_socket_path::flock_file_owned(guest, &pin).await else {
                return Ok(None);
            };
            registry.domain(identity, description.open_file_id())
        };
        description.set_flock_domain(Arc::clone(&domain));
        description.set_lock_tracked();
        crate::tool_global::event_driven_io(guest, Update::Create(domain.key, false)).await;
        let held_mode = flock_mode(&read_locks(&pin)?);
        Ok(Some(Self { pin: Some(pin), description, domain, held_mode }))
    }

    pub(crate) async fn observe<T: RecordOrReplay, G: Guest<Detcore<T>>>(
        &self,
        guest: &mut G,
        first: bool,
    ) -> Result<Box<Snapshot>, Error> {
        let snapshot = if self.domain.enabled() {
            crate::tool_global::event_driven_io(guest, Update::Observe(vec![self.domain.key], first, Vec::new())).await
        } else {
            None
        };
        match snapshot {
            Some(snapshot) => Ok(Box::new(snapshot)),
            None => {
                let reason = "blocking flock lost its closed, run-private producer set";
                tracing::error!("{reason}");
                crate::syscalls::helpers::refuse_unserviceable_operation_with(
                    guest, true, Sysno::flock, Errno::ENOLCK, Some(reason),
                ).await?;
                unreachable!("fail-closed flock refusal returned successfully")
            }
        }
    }

    pub(crate) async fn attempt<T: RecordOrReplay, G: Guest<Detcore<T>>>(
        &mut self,
        guest: &mut G,
        operation: i32,
    ) -> Result<i64, Error> {
        let pin = self.pin.as_ref().expect("live flock pin");
        let result = guest.flock_pinned(pin, operation | libc::LOCK_NB).await;
        let held = read_locks(pin)?;
        let mode = flock_mode(&held);
        let changed = mode != self.held_mode;
        self.description.set_flock_mode(mode);
        let id = self.description.open_file_id();
        let slots = guest.thread_state().slots_naming(id);
        // Publish conversion drops before parking, not only at syscall return.
        let taken = if result.is_ok() && changed {
            held.iter().filter(|lock| lock.class == "FLOCK").cloned().collect()
        } else {
            Vec::new()
        };
        crate::tool_global::note_description_locks_taken(
            guest, id, held, taken, slots, crate::procfs::locks::LedgerIdentity::Own,
        ).await;
        self.held_mode = mode;
        if changed {
            crate::tool_global::event_driven_io(guest, Update::Change(vec![self.domain.key])).await;
        }
        result
    }
}

fn flock_mode(held: &[HeldLock]) -> Option<i32> {
    held.iter().find(|lock| lock.class == "FLOCK").map(|lock| {
        if lock.access == "READ" { libc::LOCK_SH } else { libc::LOCK_EX }
    })
}

fn read_locks(pin: &PinnedFlock) -> Result<Vec<HeldLock>, Error> {
    let contents = std::fs::read(format!("/proc/self/fdinfo/{}", pin.as_fd().as_raw_fd()))
        .map_err(|error| Error::Tool(anyhow::anyhow!("cannot inspect pinned flock ownership: {error}")))?;
    Ok(crate::procfs::locks::held_locks_in_fdinfo(&contents))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DetTid;

    #[test]
    fn native_inode_recycling_does_not_change_logical_domains() {
        fn sequence(next_inode: u64) -> [Key; 3] {
            let registry = Arc::new(Registry::default());
            let id = |sequence| OpenFileId::new(DetTid::from_raw(7), sequence);
            let original = registry.domain((1, 10), id(1));
            let original_key = original.key;
            let alias = registry.domain((1, 10), id(2));
            assert_eq!(alias.key, original_key);
            drop(original);
            let still_live = registry.domain((1, 10), id(3)).key;
            drop(alias);
            let replacement = registry.domain((1, next_inode), id(4)).key;
            [original_key, still_live, replacement]
        }

        let recycled = sequence(10);
        assert_eq!(recycled[0], recycled[1]);
        assert_ne!(recycled[0], recycled[2]);
        assert_eq!(recycled, sequence(20));
    }
}
