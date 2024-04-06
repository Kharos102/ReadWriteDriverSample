#![feature(new_uninit)]
#![feature(negative_impls)]
#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

use alloc::vec;
use core::{
    arch::asm,
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicUsize},
};

use alloc::vec::Vec;
use core::sync::atomic::Ordering::SeqCst;
#[cfg(not(test))]
use wdk_alloc::WDKAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WDKAllocator = WDKAllocator;

extern crate alloc;

pub(crate) mod uni;

mod interrupts;
mod locking;
mod mdl;
pub(crate) mod shared;

use crate::interrupts::{PageFaultInterruptHandlerManager, PAGE_FAULT_HIT, PROBING_ADDRESS};
use crate::locking::{CoreLock, CorePin, CORES_CHECKED_IN, CORE_LOCK_HELD, RELEASE_CORES};
use wdk_sys::{
    ntddk::KeQueryActiveProcessorCount, DEVICE_OBJECT, DRIVER_OBJECT, NTSTATUS, NT_SUCCESS,
    PCUNICODE_STRING,
};

// Exposed device name used for user<>driver communication
const NT_DEVICE_NAME_PATH: &str = "\\Device\\ReadWriteDevice";
const DOS_DEVICE_NAME_PATH: &str = "\\DosDevices\\ReadWriteDevice";

/// Number of logical cores (NUM_LOGICAL_CORES) on the system using OnceLock and KeQueryActiveProcessorCount
static NUM_LOGICAL_CORES: AtomicUsize = AtomicUsize::new(0);

static mut PAGE_FAULT_MANAGER: Option<Vec<PageFaultInterruptHandlerManager>> = None;

/// Wrapper around the PEPROCESS handle to ensure it is dereferenced when dropped
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

#[derive(Copy, Clone)]
enum IrqlMethod {
    RaiseIrql,
    RaiseIrqlDirect,
    LowerIrql,
    LowerIrqlDirect,
}

/// Wrapper around an old IRQL value (after a call to raise IRQL) that will lower the IRQL
/// to its original value when dropped.
struct IrqlGuard {
    old_irql: u8,
    method: IrqlMethod,
}

impl Drop for IrqlGuard {
    fn drop(&mut self) {
        unsafe {
            match self.method {
                IrqlMethod::RaiseIrql => wdk_sys::ntddk::KeLowerIrql(self.old_irql),
                IrqlMethod::RaiseIrqlDirect => {
                    asm!("mov cr8, {}", in(reg) self.old_irql as u64)
                }
                IrqlMethod::LowerIrql => {
                    let _ = wdk_sys::ntddk::KfRaiseIrql(self.old_irql);
                }
                IrqlMethod::LowerIrqlDirect => {
                    asm!("mov cr8, {}", in(reg) self.old_irql as u64)
                }
            }
        }
    }
}

/// Errors that can occur when handling IOCTL requests, can be converted to NTSTATUS
enum IoctlError {
    InvalidBufferSize,
    InvalidPid,
    InvalidCr3,
    InvalidAddress,
}

impl IoctlError {
    fn status(&self) -> NTSTATUS {
        match self {
            IoctlError::InvalidBufferSize => wdk_sys::STATUS_INVALID_BUFFER_SIZE,
            IoctlError::InvalidPid => wdk_sys::STATUS_INVALID_PARAMETER,
            IoctlError::InvalidCr3 => wdk_sys::STATUS_INVALID_PARAMETER,
            IoctlError::InvalidAddress => wdk_sys::STATUS_ACCESS_VIOLATION,
        }
    }
}

/// Raise the IRQL to DISPATCH_LEVEL and return an IrqlGuard that will lower the IRQL when dropped.
/// The method used can be via the Windows API or by directly modifying cr8.
fn raise_irql_to_dispatch(method: IrqlMethod) -> IrqlGuard {
    let old_irql = match method {
        IrqlMethod::RaiseIrql => unsafe {
            wdk_sys::ntddk::KfRaiseIrql(wdk_sys::DISPATCH_LEVEL as u8)
        },
        IrqlMethod::RaiseIrqlDirect => unsafe {
            let old_irql: u64;
            asm!("mov {}, cr8", out(reg) old_irql);
            asm!("mov cr8, {}", in(reg) wdk_sys::DISPATCH_LEVEL as u64);
            old_irql as u8
        },
        _ => {
            panic!("Invalid method for raise_irql_to_dispatch")
        }
    };

    IrqlGuard { old_irql, method }
}

fn lower_irql_to_passive(method: IrqlMethod) -> IrqlGuard {
    let old_irql = match method {
        IrqlMethod::LowerIrql => unsafe {
            let old_irql = wdk_sys::ntddk::KeGetCurrentIrql();
            wdk_sys::ntddk::KeLowerIrql(wdk_sys::PASSIVE_LEVEL as u8);
            old_irql as u8
        },
        IrqlMethod::LowerIrqlDirect => unsafe {
            let old_irql: u64;
            asm!("mov {}, cr8", out(reg) old_irql);
            asm!("mov cr8, {}", in(reg) wdk_sys::PASSIVE_LEVEL as u64);
            old_irql as u8
        },
        _ => {
            panic!("Invalid method for lower_irql_to_passive")
        }
    };

    IrqlGuard { old_irql, method }
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
        NUM_LOGICAL_CORES.store(core_count, SeqCst);
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
            return if input_buffer_len < core::mem::size_of::<shared::ReadWriteIoctl>() {
                // Input buffer is too small, return invalid buffer size
                irp.IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_INVALID_BUFFER_SIZE;
                irp.IoStatus.Information = 0;
                wdk_sys::ntddk::IofCompleteRequest(irp, 0);
                wdk_sys::STATUS_INVALID_BUFFER_SIZE
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
                        wdk_sys::STATUS_SUCCESS
                    }
                    Err(e) => {
                        // Failed to handle the request, return invalid parameter
                        irp.IoStatus.__bindgen_anon_1.Status = e.status();
                        irp.IoStatus.Information = 0;
                        wdk_sys::ntddk::IofCompleteRequest(irp, 0);
                        wdk_sys::STATUS_INVALID_PARAMETER
                    }
                }
            };
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

enum CheckWriteMethod {
    WindowsApi,
    CustomPageFaultHandler,
}

fn check_and_write(
    write_request: WriteRequest,
    method: CheckWriteMethod,
) -> Result<(), IoctlError> {
    match method {
        CheckWriteMethod::WindowsApi => check_and_write_windows(write_request),
        CheckWriteMethod::CustomPageFaultHandler => check_and_write_page_fault(write_request),
    }
}

fn check_and_write_page_fault(write_request: WriteRequest) -> Result<(), IoctlError> {
    // Install our custom page fault handler
    let handler_manager = {
        // Temporarily lower IRQL to support page faults
        let _irql_guard = lower_irql_to_passive(IrqlMethod::LowerIrqlDirect);
        let current_core =
            unsafe { wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) };
        let mut handler_manager = None;
        // Check if we have one already, if so return a mutable reference
        if let Some(manager) = unsafe { &mut PAGE_FAULT_MANAGER } {
            // Attempt to find a manager with the same core_id as us
            let current_core =
                unsafe { wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) };
            for manager in manager.iter_mut() {
                if manager.core_id == current_core as u64 {
                    // Ensure things are still paged in
                    manager.page_in_idt();
                    handler_manager = Some(manager);
                    break;
                }
            }
        }
        if handler_manager.is_none() {
            // Pagein IDT
            let mdl = interrupts::pagein_unprotect_idt();
            // If we don't have one, create a new one and store it
            let manager = PageFaultInterruptHandlerManager::new(mdl, current_core as u64);
            // Add the manager to the global vector
            unsafe {
                if let Some(manager_vec) = &mut PAGE_FAULT_MANAGER {
                    manager_vec.push(manager);
                } else {
                    PAGE_FAULT_MANAGER = Some(vec![manager]);
                }
            }
            // Set handler_manager to the newly created manager
            handler_manager =
                Some(unsafe { PAGE_FAULT_MANAGER.as_mut().unwrap().last_mut().unwrap() });
        }

        handler_manager.unwrap()
    };
    handler_manager.install_interrupt_handler();

    let mut return_value = Ok(());
    // Attempt to write the buffer to the target process
    // For each byte we write, check the global PAGE_FAULT_HIT flag to see if a page fault occurred
    // If a page fault occurred, return an error
    for i in 0..write_request.buffer.len() {
        let address = write_request.untrusted_address + i;
        PROBING_ADDRESS.store(address as u64, SeqCst);
        unsafe {
            asm!(
            "mov [rdx], {}",
            in(reg_byte) write_request.buffer[i],
            in("rdx") address as u64,
            );
        }
        if PAGE_FAULT_HIT.load(SeqCst) {
            return_value = Err(IoctlError::InvalidAddress);
            break;
        }
    }

    PROBING_ADDRESS.store(0, SeqCst);

    // Restore the original page fault handler
    handler_manager.restore_interrupt_handler();

    return_value
}
fn check_and_write_windows(write_request: WriteRequest) -> Result<(), IoctlError> {
    let buffer_len = write_request.buffer.len();
    let address = write_request.untrusted_address;
    // For every byte we wish to access, we need to ensure the address is accessible. As we've guaranteed all other cores are frozen and
    // our thread cannot be task-switched, we can trust the result of the following checks as there is no opportunity for another thread
    // to modify the state of the target process.
    // Loop through each address we intend to touch (starting at the provided address, and ending at the provided address + buffer_len) and ensure the
    // result of a call to MmIsAddressValid is true. If it is not, return an error.
    for i in 0..buffer_len {
        let address = address + i;
        if unsafe { wdk_sys::ntddk::MmIsAddressValid(address as *mut c_void) } != 1 {
            return Err(IoctlError::InvalidAddress);
        }
    }

    // Copy buffer to address as requested by user.
    unsafe {
        core::ptr::copy_nonoverlapping(
            write_request.buffer.as_ptr(),
            address as *mut u8,
            buffer_len,
        );
    }

    Ok(())
}

fn switch_cr3(new_cr3: usize) -> Cr3SwitchGuard {
    let previous_cr3 = unsafe {
        let mut previous_cr3: usize = 0;
        asm!(
            "mov {}, cr3",
            out(reg) previous_cr3,
        );
        asm!(
            "mov cr3, {}",
            in(reg) new_cr3,
        );
        previous_cr3
    };

    Cr3SwitchGuard { previous_cr3 }
}

struct Cr3SwitchGuard {
    previous_cr3: usize,
}

impl Drop for Cr3SwitchGuard {
    fn drop(&mut self) {
        unsafe {
            asm!(
                "mov cr3, {}",
                in(reg) self.previous_cr3,
            );
        }
    }
}

#[derive(Clone)]
struct WriteRequest<'a> {
    untrusted_address: usize,
    buffer: &'a [u8],
}

/// Attempt to handle the ReadWriteIoctl request. This function will attempt to locate the target process
/// by PID, and then copy the provided buffer to the target process's memory.
fn handle_ioctl_request(
    ioctl_request: &shared::ReadWriteIoctl,
    buffer_len_max: usize,
) -> Result<(), IoctlError> {
    let header = &ioctl_request.header;
    let address = header.address;
    let buffer_len = header.buffer_len;

    // Pin the executing thread to the current core, as we mess with IDTs later
    // we want to ensure we're not task-switched to another core with a separate IDT.
    // This will auto-revert when dropped (end of function)
    let _core_pin = CorePin::new();

    // If we're attempting to write 0 bytes, we can just return success now
    if buffer_len == 0 {
        return Ok(());
    }
    // Validate that the entire ReadWriteIoctl request (incl. dynamic buffer) is within the input buffer max bounds
    if core::mem::size_of::<shared::ReadWriteIoctl>() + buffer_len > buffer_len_max {
        // The size of the provided ioctl_request (including the dynamic buffer portion) exceeds the bounds of the provided input buffer,
        // if we continued to parse the request we'd be reading out of bounds. Return an error.
        return Err(IoctlError::InvalidBufferSize);
    }
    // The dynamic buffer portion is of a dynamic length, so we need to convert it to a slice
    // using the provided buffer_len.
    let buffer =
        unsafe { core::slice::from_raw_parts(&ioctl_request.buffer as *const u8, buffer_len) };
    // Get the KPROCESS from the target_pid if it exists, or return an error
    let process = match process_from_pid(header.target_pid) {
        Some(process) => process,
        None => return Err(IoctlError::InvalidPid),
    };

    // Get offset 0x28 from the KPROCESS which is the DirectoryTableBase / cr3
    let cr3 = unsafe {
        let cr3_offset = 0x28;
        let cr3_ptr = (process.handle as *const u8).add(cr3_offset) as *const usize;
        *cr3_ptr
    };

    // Check if our obtained cr3 is likely to be a valid cr3
    if !is_likely_cr3(cr3) {
        return Err(IoctlError::InvalidCr3);
    }

    {
        // Freeze all other cores on the system to prevent any other threads from modifying the target process
        let _lock = freeze_all_cores();
        {
            // Raise our IRQL to prevent task-switching
            let _irql_guard = raise_irql_to_dispatch(IrqlMethod::RaiseIrqlDirect);
            // Modify our CR3 to the targets, backing up our original cr3
            // and auto-restoring on drop
            let _cr3_guard = switch_cr3(cr3);

            let write_request = WriteRequest {
                untrusted_address: address,
                buffer,
            };

            check_and_write(write_request, CheckWriteMethod::CustomPageFaultHandler)?;

            // irql_guard and cr3_guard will be dropped (or dropped already if check_and_write
            // threw an error), auto lowering the irql and restoring the cr3
        }

        // _lock will be dropped, auto releasing the cores
    }

    // Success
    Ok(())
}

/// Freeze all cores on the system. Returns a `CoreLock` which will release the cores when dropped.
fn freeze_all_cores() -> CoreLock {
    // Ensure the cores are not already locked, if not swap the lock to true
    if CORE_LOCK_HELD.swap(true, SeqCst) {
        panic!("Cores are already locked");
    }
    // Create a vector to store the allocated DPCs for cleanup
    let mut allocated_dpcs = Vec::with_capacity(NUM_LOGICAL_CORES.load(SeqCst));

    for _core in 0..(NUM_LOGICAL_CORES.load(SeqCst) - 1) {
        let tag = 0x647772;
        // Create a DPC for the core
        // The DPC should be allocated from NonPagedPool, allocate it using ExAllocatePool2
        unsafe {
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
        };
    }

    {
        // Temporarily raise to dispatch to prevent being rescheduled onto a different core
        let _irql_guard = raise_irql_to_dispatch(IrqlMethod::RaiseIrqlDirect);
        // Don't freeze the current core
        let current_core =
            unsafe { wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) }
                as usize;

        // Clone the allocated_dpcs as we're going to temporarily pop them
        let mut allocated_dpcs_clone = allocated_dpcs.clone();
        // Create a DPC for NUM_LOGICAL_CORES - 1 (skipping the current core)
        for core in 0..NUM_LOGICAL_CORES.load(SeqCst) {
            // If its the current core, skip
            if core == current_core {
                continue;
            }
            // If its not, pop a DPC out of the allocated_dpcs_clone
            let dpc = allocated_dpcs_clone.pop().expect("Failed to pop DPC");
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

    // Wait for all other cores to check in to ensure they are frozen before we proceed further
    while CORES_CHECKED_IN.load(SeqCst) < NUM_LOGICAL_CORES.load(SeqCst) - 1 {
        // Spin/wait
    }
    // All cores have checked in, return the CoreLock
    CoreLock::new(allocated_dpcs)
}

/// Freezes a core by raising the IRQL to DISPATCH_LEVEL, checking in the core and waiting for the release signal.
#[inline(never)]
unsafe extern "C" fn freeze_core(
    _kdpc: *mut wdk_sys::KDPC,
    _deferred_context: *mut c_void,
    _system_argument1: *mut c_void,
    _system_argument2: *mut c_void,
) {
    // Raise IRQL to DISPATCH_LEVEL to prevent task-switching, ensuring our thread is the only one running on the core
    let _irql_guard = raise_irql_to_dispatch(IrqlMethod::RaiseIrqlDirect);
    // Check in the core to indicate it is frozen
    CORES_CHECKED_IN.fetch_add(1, SeqCst);
    // Wait for the release signal
    while !RELEASE_CORES.load(SeqCst) {
        // Spin/wait
    }
    // Release signal received, check-out the core as we will no longer freeze this core
    CORES_CHECKED_IN.fetch_sub(1, SeqCst);

    // irql_guard will be dropped, auto lowering the irql
}

/// Attempt to locate the process by PID. If found, return the a wrapper to it, otherwise return None.
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
    // Check if any cores are currently frozen, this should never happen.
    // If they are frozen, wait a little to see if they unfreeze and if not, panic.
    if CORES_CHECKED_IN.load(SeqCst) > 0 {
        for _ in 0..1000 {
            // Spin
        }
        panic!("Cores are still frozen while attempting to unload the driver");
    }

    // Delete symbolic link
    let dos_device_name = uni::str_to_unicode(DOS_DEVICE_NAME_PATH);
    let mut dos_device_name_uni = dos_device_name.to_unicode();
    let _status = wdk_sys::ntddk::IoDeleteSymbolicLink(&mut dos_device_name_uni);

    // If we have a device, delete it
    if !(*driver_obj).DeviceObject.is_null() {
        wdk_sys::ntddk::IoDeleteDevice((*driver_obj).DeviceObject);
    }
}

/// Return whether the provided address/usize appears to be on a page boundary
fn is_page_aligned(address: usize) -> bool {
    address & 0xFFF == 0
}

/// Checks whether the provided value appears to be a valid CR3.
/// This only guesses by performing a few checks that apply to how CR3 values are
/// used on Windows, but are not strictly guaranteed to be true.
fn is_likely_cr3(cr3: usize) -> bool {
    // Check if the value is page aligned, less than 0x0000_FFFF_FFFF_FFFF, and non-zero
    const CR3_EXPECTED_MAX: usize = 0x0000_FFFF_FFFF_FFFF;
    is_page_aligned(cr3) && cr3 < CR3_EXPECTED_MAX && cr3 != 0
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
