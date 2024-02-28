#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

use core::{
    arch::asm,
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicUsize},
};

use alloc::vec::Vec;
#[cfg(not(test))]
use wdk_alloc::WDKAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WDKAllocator = WDKAllocator;

extern crate alloc;

pub(crate) mod uni;

pub(crate) mod shared;

use wdk_sys::{
    ntddk::KeQueryActiveProcessorCount, DEVICE_OBJECT, DRIVER_OBJECT, NTSTATUS, NT_SUCCESS,
    PCUNICODE_STRING,
};

// Exposed device name used for user<>driver communication
const NT_DEVICE_NAME_PATH: &str = "\\Device\\ReadWriteDevice";
const DOS_DEVICE_NAME_PATH: &str = "\\DosDevices\\ReadWriteDevice";

/// Number of logical cores (NUM_LOGICAL_CORES) on the system using OnceLock and KeQueryActiveProcessorCount
static NUM_LOGICAL_CORES: AtomicUsize = AtomicUsize::new(0);

/// Flag indicating if the cores should be released
static RELEASE_CORES: AtomicBool = AtomicBool::new(false);

/// Number of cores currently checked-in / on hold
static CORES_CHECKED_IN: AtomicUsize = AtomicUsize::new(0);

static CORE_LOCK_HELD: AtomicBool = AtomicBool::new(false);

struct CoreLock {
    allocated_dpcs: Vec<*mut wdk_sys::KDPC>,
}

struct PeProcessHandle {
    handle: wdk_sys::PEPROCESS,
}

impl Drop for PeProcessHandle {
    fn drop(&mut self) {
        unsafe {
            wdk_sys::ntddk::ObfDereferenceObject(self.handle as *mut c_void);
        }
    }
}

// Impl drop for corelock that will set the release cores flag to true, wait for
// all cores to check out, and then reset the core lock held flag.
impl Drop for CoreLock {
    fn drop(&mut self) {
        // Set the release flag
        RELEASE_CORES.store(true, core::sync::atomic::Ordering::SeqCst);
        // Wait for all cores to check out
        while CORES_CHECKED_IN.load(core::sync::atomic::Ordering::SeqCst) > 0 {
            // Spin
        }
        // All cores have checked out, reset the release flag
        RELEASE_CORES.store(false, core::sync::atomic::Ordering::SeqCst);

        // Reset the core lock held flag
        CORE_LOCK_HELD.store(false, core::sync::atomic::Ordering::SeqCst);

        // Free the allocated DPCs
        for dpc in self.allocated_dpcs.iter() {
            unsafe {
                wdk_sys::ntddk::ExFreePool(*dpc as *mut c_void);
            }
        }
    }
}

#[export_name = "DriverEntry"] // WDF expects a symbol with the name DriverEntry
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    // Device names for NT and Dos in unicode, as required by the kernel APIs
    let nt_device_name = uni::str_to_unicode(NT_DEVICE_NAME_PATH);
    let dos_device_name = uni::str_to_unicode(DOS_DEVICE_NAME_PATH);
    // Device object handle to be filled by IoCreateDevice
    let mut device_obj: *mut DEVICE_OBJECT = core::ptr::null_mut();

    let status = {
        let mut nt_device_name_uni = nt_device_name.to_unicode();
        wdk_sys::ntddk::IoCreateDevice(
            driver,
            0,
            &mut nt_device_name_uni,
            wdk_sys::FILE_DEVICE_UNKNOWN,
            wdk_sys::FILE_DEVICE_SECURE_OPEN,
            0,
            &mut device_obj,
        )
    };
    if !NT_SUCCESS(status) {
        // Fail
        return status;
    }
    // Set required MajorFunction handlers to permit DeviceIoControl calls from user
    driver.MajorFunction[wdk_sys::IRP_MJ_CREATE as usize] = Some(device_create_close);
    driver.MajorFunction[wdk_sys::IRP_MJ_CLOSE as usize] = Some(device_create_close);
    driver.MajorFunction[wdk_sys::IRP_MJ_DEVICE_CONTROL as usize] = Some(device_ioctl_handler);
    // Support unloading the driver
    driver.DriverUnload = Some(device_unload);

    // Create symbolic link to device, required for user mode to access the device
    let status = {
        let mut nt_device_name_uni = nt_device_name.to_unicode();
        let mut dos_device_name_uni = dos_device_name.to_unicode();
        wdk_sys::ntddk::IoCreateSymbolicLink(&mut dos_device_name_uni, &mut nt_device_name_uni)
    };
    if !NT_SUCCESS(status) {
        // If failed, cleanup device object and return
        wdk_sys::ntddk::IoDeleteDevice(device_obj);
        return status;
    }

    // Initialize the number of logical cores
    {
        let core_count = unsafe { KeQueryActiveProcessorCount(core::ptr::null_mut()) as usize };
        NUM_LOGICAL_CORES.store(core_count, core::sync::atomic::Ordering::SeqCst);
    }

    // At this point we have a device and a symbolic link, return success
    wdk_sys::STATUS_SUCCESS
}

/// Entry point to handle DeviceIoControl calls from user. Expects a ReadWriteIoctl struct as input.
pub unsafe extern "C" fn device_ioctl_handler(
    _dev_obj: *mut DEVICE_OBJECT,
    irp: *mut wdk_sys::IRP,
) -> NTSTATUS {
    // Get the control code and input buffer from the IRP
    let irp = &mut *irp;
    let stack = &*irp
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation;
    let control_code = stack.Parameters.DeviceIoControl.IoControlCode;
    // Get input buffer and len
    let input_buffer = irp.AssociatedIrp.SystemBuffer;
    let input_buffer_len = stack.Parameters.DeviceIoControl.InputBufferLength as usize;

    // Check for our supported IOCTL_REQUEST command or return invalid device request
    match control_code {
        shared::IOCTL_REQUEST => {
            // Matched on our IOCTL_REQUEST command. Check input buffer len and handle the request.
            // The input buffer should be at least the size of the ReadWriteIoctl struct
            if input_buffer_len < core::mem::size_of::<shared::ReadWriteIoctl>() {
                // Input buffer is too small, return invalid buffer size
                irp.IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_INVALID_BUFFER_SIZE;
                irp.IoStatus.Information = 0;
                wdk_sys::ntddk::IofCompleteRequest(irp, 0);
                return wdk_sys::STATUS_INVALID_BUFFER_SIZE;
            } else {
                // Input buffer is large enough, handle the request.
                // First, cast the input buffer to a ReadWriteIoctl struct
                let ioctl_request = &*(input_buffer as *const shared::ReadWriteIoctl);
                // Attempt to handle the request
                match handle_ioctl_request(ioctl_request, input_buffer_len) {
                    Ok(_) => {
                        // Handled the request successfully, return success
                        irp.IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_SUCCESS;
                        irp.IoStatus.Information = 0;
                        wdk_sys::ntddk::IofCompleteRequest(irp, 0);
                        return wdk_sys::STATUS_SUCCESS;
                    }
                    Err(_) => {
                        // Failed to handle the request, return invalid parameter
                        irp.IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_INVALID_PARAMETER;
                        irp.IoStatus.Information = 0;
                        wdk_sys::ntddk::IofCompleteRequest(irp, 0);
                        return wdk_sys::STATUS_INVALID_PARAMETER;
                    }
                }
            }
        }
        _ => {
            // Unsupported IOCTL command, return invalid device request
            irp.IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_INVALID_DEVICE_REQUEST;
            irp.IoStatus.Information = 0;
            wdk_sys::ntddk::IofCompleteRequest(irp, 0);
            wdk_sys::STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

/// Attempt to handle the ReadWriteIoctl request. This function will attempt to locate the target process
/// by PID, and then copy the provided buffer to the target process's memory.
fn handle_ioctl_request(
    ioctl_request: &shared::ReadWriteIoctl,
    buffer_len_max: usize,
) -> Result<(), ()> {
    let header = &ioctl_request.header;
    let address = header.address;
    let buffer_len = header.buffer_len;
    // Validate that the entire ReadWriteIoctl request (incl. dynamic buffer) is within the input buffer max bounds
    if core::mem::size_of::<shared::ReadWriteIoctl>() + buffer_len > buffer_len_max {
        // The size of the provided ioctl_request (including the dynamic buffer portion) exceeds the bounds of the provided input buffer,
        // if we continued to parse the request we'd be reading out of bounds. Return an error.
        return Err(());
    }
    // The dynamic buffer portion is of a dynamic length, so we need to convert it to a slice
    // using the provided buffer_len.
    let buffer =
        unsafe { core::slice::from_raw_parts(&ioctl_request.buffer as *const u8, buffer_len) };
    // Get the KPROCESS from the target_pid if it exists, or return an error
    let process = match process_from_pid(header.target_pid) {
        Some(process) => process,
        None => return Err(()),
    };

    // Get offset 0x28 from the KPROCESS which is the DirectoryTableBase / cr3
    let cr3 = unsafe {
        let cr3_offset = 0x28;
        let cr3_ptr = (process.handle as *const u8).add(cr3_offset) as *const usize;
        *cr3_ptr
    };

    {
        let _lock = freeze_all_cores();

        // Raise IRQL to DISPATCH_LEVEL using KfRaiseIrql to prevent context switches while using the target's cr3
        let old_irql = unsafe { wdk_sys::ntddk::KfRaiseIrql(wdk_sys::DISPATCH_LEVEL as u8) };
        // Modify our CR3 to the targets, backing up our original cr3
        let old_cr3: usize;
        unsafe {
            asm!("mov {}, cr3", out(reg) old_cr3);
            asm!("mov cr3, {}", in(reg) cr3);
        }
        // Copy buffer to address as requested by user.
        // SAFETY: We don't verify the provided address is valid, accessible / paged-in or writable at all. This can result in
        // exceptions or faults. That combined with being in DISPATCH_LEVEL makes this a dangerous operation.
        // We should be probing and locking pages for safety.
        unsafe {
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), address as *mut u8, buffer_len);
        }

        // Restore our previous cr3
        unsafe {
            asm!("mov cr3, {}", in(reg) old_cr3);
        }

        // Lower IRQL to our previous level
        unsafe { wdk_sys::ntddk::KeLowerIrql(old_irql) };

        // _lock will be dropped, auto releasing the cores
    }

    // Success
    Ok(())
}

/// Freeze all cores on the system. Returns a `CoreLock` which will release the cores when dropped.
fn freeze_all_cores() -> CoreLock {
    // Ensure the cores are not already locked, if not swap the lock to true
    if CORE_LOCK_HELD.swap(true, core::sync::atomic::Ordering::SeqCst) {
        panic!("Cores are already locked");
    }

    let mut allocated_dpcs =
        Vec::with_capacity(NUM_LOGICAL_CORES.load(core::sync::atomic::Ordering::SeqCst));

    // For all cores (except the current core), Create a DPC with KeInitializeDpc and KeSetTargetProcessorDpc
    // to freeze the core. Then, wait for all cores to check in and return the CoreLock.
    let current_core =
        unsafe { wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) } as usize;
    for core in 0..NUM_LOGICAL_CORES.load(core::sync::atomic::Ordering::SeqCst) {
        if core != current_core {
            let tag = 0x647772;
            // Create a DPC for the core
            // The DPC should be allocated from NonPagedPool, allocate it using ExAllocatePool2
            let dpc = unsafe {
                let buffer = wdk_sys::ntddk::ExAllocatePool2(
                    wdk_sys::POOL_FLAG_NON_PAGED,
                    core::mem::size_of::<wdk_sys::KDPC>() as u64,
                    tag,
                ) as *mut wdk_sys::KDPC;

                // Assert the buffer is non-null
                assert_ne!(buffer, core::ptr::null_mut());
                // Write a default KDPC to the buffer
                core::ptr::write(buffer, wdk_sys::KDPC::default());

                // Store the allocated DPC for cleanup
                allocated_dpcs.push(buffer);

                // Send up the default non-paged initialized KDPC
                buffer
            };

            // Initialize the DPC
            unsafe {
                wdk_sys::ntddk::KeInitializeDpc(dpc, Some(freeze_core), core::ptr::null_mut());
            }
            // Set the target processor for the DPC
            unsafe {
                wdk_sys::ntddk::KeSetTargetProcessorDpc(dpc, core as i8);
                // Queue the DPC
                wdk_sys::ntddk::KeInsertQueueDpc(dpc, core::ptr::null_mut(), core::ptr::null_mut());
            }
        }
    }
    // Wait for all cores to check in
    while CORES_CHECKED_IN.load(core::sync::atomic::Ordering::SeqCst)
        < NUM_LOGICAL_CORES.load(core::sync::atomic::Ordering::SeqCst) - 1
    {
        // Spin
    }
    // All cores have checked in, return the CoreLock
    CoreLock { allocated_dpcs }
}

/// Freezes a core by raising the IRQL to DISPATCH_LEVEL, checking in the core and waiting for the release signal.
#[inline(never)]
unsafe extern "C" fn freeze_core(
    _kdpc: *mut wdk_sys::KDPC,
    _deferred_context: *mut c_void,
    _system_argument1: *mut c_void,
    _system_argument2: *mut c_void,
) {
    // Raise IRQL to DISPATCH_LEVEL
    let old_irql = unsafe { wdk_sys::ntddk::KfRaiseIrql(wdk_sys::DISPATCH_LEVEL as u8) };
    // Check in the core
    CORES_CHECKED_IN.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    // Wait for the release signal
    while !RELEASE_CORES.load(core::sync::atomic::Ordering::SeqCst) {
        // Spin
    }
    // Release signal received, check-out the core
    CORES_CHECKED_IN.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);

    // Lower IRQL to our previous level
    unsafe { wdk_sys::ntddk::KeLowerIrql(old_irql) };
}

/// Attempt to locate the process by PID. If found, return the PEPROCESS pointer, otherwise return None.
fn process_from_pid(pid: u32) -> Option<PeProcessHandle> {
    let mut handle: wdk_sys::PEPROCESS = core::ptr::null_mut();
    let status =
        unsafe { wdk_sys::ntddk::PsLookupProcessByProcessId(pid as *mut c_void, &mut handle) };
    if NT_SUCCESS(status) {
        Some(PeProcessHandle { handle })
    } else {
        None
    }
}

/// Unload the driver. This function will delete the symbolic link and the device object if it exists.
pub unsafe extern "C" fn device_unload(driver_obj: *mut DRIVER_OBJECT) {
    // Delete symbolic link
    let dos_device_name = uni::str_to_unicode(DOS_DEVICE_NAME_PATH);
    let mut dos_device_name_uni = dos_device_name.to_unicode();
    let _status = wdk_sys::ntddk::IoDeleteSymbolicLink(&mut dos_device_name_uni);

    // If we have a device, delete it
    if !(*driver_obj).DeviceObject.is_null() {
        wdk_sys::ntddk::IoDeleteDevice((*driver_obj).DeviceObject);
    }
}

/// Create and close handlers for the device object. These are required to permit DeviceIoControl calls from user.
/// We allow create and close to pass through without any action.
pub unsafe extern "C" fn device_create_close(
    _dev_obj: *mut DEVICE_OBJECT,
    irp: *mut wdk_sys::IRP,
) -> NTSTATUS {
    let irp = &mut *irp;
    irp.IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_SUCCESS;
    irp.IoStatus.Information = 0;
    wdk_sys::ntddk::IofCompleteRequest(irp, 0);

    wdk_sys::STATUS_SUCCESS
}
