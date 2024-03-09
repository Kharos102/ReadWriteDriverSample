use core::ptr::null_mut;
use wdk_sys::{BOOLEAN, KPROCESSOR_MODE, PAGE_EXECUTE_READWRITE, PMDL, ULONG};
use wdk_sys::_MEMORY_CACHING_TYPE::MmNonCached;
use wdk_sys::_MM_PAGE_PRIORITY::HighPagePriority;
use wdk_sys::_MODE::KernelMode;
use wdk_sys::ntddk::{IoAllocateMdl, IoFreeMdl, MmBuildMdlForNonPagedPool, MmMapLockedPagesSpecifyCache, MmProtectMdlSystemAddress};

pub(crate) struct MyMDL {
    mdl: PMDL,
    pub(crate) mapped_base: u64,
}

impl Drop for MyMDL {
    fn drop(&mut self) {
        unsafe {
            IoFreeMdl(self.mdl);
        }
    }
}

// Build an MDL for the provided base address + size using IoAllocateMdl
pub(crate) fn build_mdl(base: u64, size: u64) -> Result<MyMDL, ()> {
    let mdl = unsafe { IoAllocateMdl(base as *mut _, size as u32, BOOLEAN::from(false), BOOLEAN::from(false), null_mut()) };
    if mdl.is_null() {
        return Err(());
    }
    let mapped_base = unsafe {
        MmBuildMdlForNonPagedPool(mdl);
        // Lock the mdl with MmMapLockedPagesSpecifyCache
        MmMapLockedPagesSpecifyCache(mdl, KernelMode as KPROCESSOR_MODE, MmNonCached, null_mut(), 1, HighPagePriority as ULONG) as u64
    };

    Ok(MyMDL { mdl, mapped_base })
}

// Makes the MDL pages writeable using MmProtectMdlSystemAddress
pub(crate) fn make_mdl_pages_writeable(mdl: &MyMDL) {
    let result = unsafe { MmProtectMdlSystemAddress(mdl.mdl,PAGE_EXECUTE_READWRITE) };
    if result != 0 {
        panic!("MmProtectMdlSystemAddress failed with error code {:#x}", result);
    }
}