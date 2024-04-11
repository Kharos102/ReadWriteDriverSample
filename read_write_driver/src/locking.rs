// no_std QueuedLock struct that wraps a T and provides a lock() method that
// atomically locks the T and returns a QueuedLockGuard that unlocks the T when it
// goes out of scope. Uses Atomics and a ticket approach to obtain the lock
// and ensure callers are provided access in the order they requested it.

use crate::cpu::rdtsc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::panic::Location;
use core::sync::atomic::Ordering::SeqCst;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use lazy_static::lazy_static;
use wdk_sys::ntddk::{KeRevertToUserAffinityThreadEx, KeSetSystemAffinityThreadEx};

/// Flag indicating if the cores should be released
pub static RELEASE_CORES: AtomicBool = AtomicBool::new(false);

/// Number of cores currently checked-in / on hold when freezing cores
pub static CORES_CHECKED_IN: AtomicUsize = AtomicUsize::new(0);

/// Flag indicating if the global core lock is held, used when freezing cores
pub static CORE_LOCK_HELD: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockError {
    CoreAlreadyPinned,
    CoreNotPinned,
}

lazy_static! {
    static ref PINNED_CORES: [QueuedLock<PinnedCore>; 64] = {
        let pinned_cores = core::array::from_fn(|_| {
            QueuedLock::new(PinnedCore {
                core_id: AtomicUsize::new(0),
                is_pinned: AtomicBool::new(false),
            })
        });

        pinned_cores
    };
}

struct PinnedCore {
    core_id: AtomicUsize,
    is_pinned: AtomicBool,
}

pub struct QueuedLock<T> {
    ticket: AtomicUsize,
    serving: AtomicUsize,
    caller_location: AtomicUsize,
    data: UnsafeCell<T>,
}

unsafe impl<T> Send for QueuedLock<T> {}
unsafe impl<T> Sync for QueuedLock<T> {}

pub struct QueuedLockGuard<'a, T> {
    lock: &'a QueuedLock<T>,
}

impl<T> QueuedLock<T> {
    pub const fn new(data: T) -> Self {
        // Get the current core and pin
        Self {
            ticket: AtomicUsize::new(0),
            serving: AtomicUsize::new(0),
            caller_location: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
        }
    }

    #[track_caller]
    pub fn lock(&self) -> QueuedLockGuard<T> {
        let ticket = self.ticket.fetch_add(1, SeqCst);
        let mut fast_threshold: usize = 20_000;
        let mut timeout: u64 = 0;
        while self.serving.load(SeqCst) != ticket {
            if fast_threshold > 0 {
                fast_threshold -= 1;
                continue;
            } else {
                if timeout == 0 {
                    timeout = unsafe { rdtsc() } + 3_000_000_000 * 5;
                } else {
                    if unsafe { rdtsc() } > timeout {
                        panic!("Lock timeout");
                    }
                    let caller_location = self.caller_location.load(SeqCst);
                    if caller_location > 0 {
                        let caller_location = caller_location as *const Location<'static>;
                        panic!("Lock timeout with previous holder at: {:?}", unsafe {
                            &*caller_location
                        });
                    } else {
                        panic!("Lock timeout with unknown previous holder");
                    }
                }
            }
        }
        // track location
        self.caller_location
            .store(Location::caller() as *const _ as usize, SeqCst);
        QueuedLockGuard { lock: self }
    }
}

impl<T> Drop for QueuedLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.serving.fetch_add(1, SeqCst);
    }
}

impl<T> core::ops::Deref for QueuedLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> core::ops::DerefMut for QueuedLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

pub struct CorePin {
    previous_affinity: AtomicU64,
}

// Impl new on CorePin that will pin the current thread to the current core
impl CorePin {
    pub fn new() -> Result<CorePin, LockError> {
        let current_core = unsafe {
            wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) as usize
        };
        let previous_affinity = pin_to_core(current_core)?;
        Ok(CorePin {
            previous_affinity: AtomicU64::new(previous_affinity),
        })
    }
}

// Impl drop on CorePin that will restore the previous affinity when dropped
impl Drop for CorePin {
    fn drop(&mut self) {
        unpin_core(self.previous_affinity.load(SeqCst)).expect("Failed to unpin core");
    }
}

/// CoreLock is a struct that is held when the cores are frozen, and released when the cores are unfrozen.
/// Cores are frozen by scheduling a DPC on each core to raise the IRQL to DISPATCH_LEVEL, and then checked in.
/// We track all allocated DPCs so that we can free them when the CoreLock is dropped.
pub struct CoreLock {
    allocated_dpcs: Vec<*mut wdk_sys::KDPC>,
}

impl CoreLock {
    pub fn new(allocated_dpcs: Vec<*mut wdk_sys::KDPC>) -> Self {
        CoreLock { allocated_dpcs }
    }
}

// Impl drop for corelock that will set the release cores flag to true, wait for
// all cores to check out, and then reset the core lock held flag.
impl Drop for CoreLock {
    fn drop(&mut self) {
        // Set the release flag
        RELEASE_CORES.store(true, SeqCst);
        // Wait for all cores to check out
        while CORES_CHECKED_IN.load(SeqCst) > 0 {
            // Spin
        }
        // All cores have checked out, reset the release flag
        RELEASE_CORES.store(false, SeqCst);

        // Reset the core lock held flag
        CORE_LOCK_HELD.store(false, SeqCst);

        // Free the allocated DPCs
        for dpc in self.allocated_dpcs.iter() {
            unsafe {
                wdk_sys::ntddk::ExFreePool(*dpc as *mut c_void);
            }
        }
    }
}

pub fn pin_to_core(core_id: usize) -> Result<u64, LockError> {
    let target_core_lock = &PINNED_CORES[core_id];
    let target_core = target_core_lock.lock();
    if target_core
        .is_pinned
        .compare_exchange(false, true, SeqCst, SeqCst)
        .is_err()
    {
        return Err(LockError::CoreAlreadyPinned);
    }
    target_core.core_id.store(core_id, SeqCst);
    let previous_affinity = unsafe { KeSetSystemAffinityThreadEx(1 << core_id) };
    Ok(previous_affinity)
}

pub fn unpin_core(previous_affinity: u64) -> Result<(), LockError> {
    // We can only unpin the current core
    let core_id =
        unsafe { wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) as usize };
    let target_core_lock = &PINNED_CORES[core_id];
    let target_core = target_core_lock.lock();
    if target_core
        .is_pinned
        .compare_exchange(true, false, SeqCst, SeqCst)
        .is_err()
    {
        return Err(LockError::CoreNotPinned);
    }
    unsafe {
        KeRevertToUserAffinityThreadEx(previous_affinity);
    }
    Ok(())
}
