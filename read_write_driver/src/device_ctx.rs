use crate::interrupts::{PageFaultInterruptHandlerManager, SegmentTable};
use crate::locking::{PinnedCore, QueuedLock};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicUsize;

#[derive(Default)]
pub struct Ctx {
    pub frozen_cores: FrozenCoresInfo,
    pub cached_idts: QueuedLock<Vec<Arc<QueuedLock<SegmentTable>>>>,
    pub pinned_cores: QueuedLock<Vec<PinnedCore>>,
    pub logical_core_count: AtomicUsize,
    pub page_fault_managers: QueuedLock<Vec<PageFaultInterruptHandlerManager>>,
}

#[derive(Default)]
struct FrozenCoresInfo {
    pub status: QueuedLock<CoreFreezeStatus>,
}

#[derive(Default)]
pub enum CoreFreezeStatus {
    /// Indicates cores are frozen or should be frozen, contains the number of cores currently frozen
    Frozen(AtomicUsize),
    /// Indicates cores are released or should be released, contains the number of cores still frozen
    Release(AtomicUsize),
    #[default]
    None,
}

// Impl Eq and PartialEq for CoreFreezeStatus based on the type only and not any inner values
impl Eq for CoreFreezeStatus {}

impl PartialEq for CoreFreezeStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CoreFreezeStatus::Frozen(_), CoreFreezeStatus::Frozen(_)) => true,
            (CoreFreezeStatus::Release(_), CoreFreezeStatus::Release(_)) => true,
            (CoreFreezeStatus::None, CoreFreezeStatus::None) => true,
            _ => false,
        }
    }
}
