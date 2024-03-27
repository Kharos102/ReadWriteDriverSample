use crate::mdl::{build_mdl, make_mdl_pages_writeable, MyMDL};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::hint::black_box;
use core::ops::{Deref, DerefMut};
use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering::SeqCst;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
pub(crate) static PAGE_FAULT_HIT: AtomicBool = AtomicBool::new(false);

pub(crate) static PREVIOUS_PAGE_FAULT_HANDLER: AtomicUsize = AtomicUsize::new(0);

pub(crate) static PROBING_ADDRESS: AtomicU64 = AtomicU64::new(0);

pub(crate) static mut CACHED_IDT: Option<Vec<Arc<SegmentTable>>> = None;

static mut JUNK: u64 = 0;

extern "C" {
    fn page_fault_handler();
}

// Interrupt lock will guard the provided raw pointer by only allowing access
// when going through our `lock()` function that disables interrupts with the `cli` instruction
// and provides an InterruptGuard that re-enables interrupts with the `sti` instruction when dropped.
pub(crate) struct InterruptLock<T> {
    value: UnsafeCell<T>,
}

impl<T> InterruptLock<T> {
    pub(crate) fn new(value: T) -> Self {
        InterruptLock {
            value: UnsafeCell::new(value),
        }
    }

    pub(crate) fn lock(&self) -> InterruptGuard<T> {
        // Disable interrupts
        unsafe {
            asm!("cli");
        }
        InterruptGuard { cell: self }
    }
}

pub struct InterruptGuard<'a, T> {
    cell: &'a InterruptLock<T>,
}

impl<'a, T> Drop for InterruptGuard<'a, T> {
    fn drop(&mut self) {
        // Re-enable interrupts
        unsafe {
            asm!("sti");
        }
    }
}

impl<'a, T> Deref for InterruptGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.cell.value.get() }
    }
}

impl<'a, T> DerefMut for InterruptGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.cell.value.get() }
    }
}

#[derive(Copy, Clone)]
#[repr(C, packed(1))]
pub(crate) struct IdtEntry64Raw {
    offset_1: u16,
    selector: u16,
    ist: u8,
    types_attr: u8,
    offset_2: u16,
    offset_3: u32,
    reserved: u32,
}

pub(crate) struct IdtEntry64 {
    raw_entry: InterruptLock<*mut IdtEntry64Raw>,
    vector: u64,
}

impl IdtEntry64 {
    fn replace_handler_address(&self, handler: &HandlerAddress) {
        let handler_address = handler.0;
        let raw_entry = self.raw_entry.lock();

        // Get the old handler address from the previous entry
        let raw_entry_copy = unsafe { core::ptr::read_volatile(*raw_entry) };

        let old_handler_address = {
            let offset_1 = raw_entry_copy.offset_1 as u64;
            let offset_2 = raw_entry_copy.offset_2 as u64;
            let offset_3 = raw_entry_copy.offset_3 as u64;
            offset_1 | (offset_2 << 16) | (offset_3 << 32)
        };

        let new_entry = IdtEntry64Raw {
            offset_1: handler_address as u16,
            selector: raw_entry_copy.selector,
            ist: raw_entry_copy.ist,
            types_attr: raw_entry_copy.types_attr,
            offset_2: (handler_address >> 16) as u16,
            offset_3: (handler_address >> 32) as u32,
            reserved: raw_entry_copy.reserved,
        };

        // Replace the handler address in the IDT entry with the provided handler address.
        unsafe {
            // First, flush the cache containing the raw_entry address using clflush
            // Call this for every 8 bytes of the raw_entry address (based on size of IdtEntry64Raw)
            asm!("wbinvd");
            // Synchronize
            asm!("mfence");
            core::ptr::write_volatile(*raw_entry, new_entry);
        }

        // Store the old handler address in our atomic global
        PREVIOUS_PAGE_FAULT_HANDLER.store(old_handler_address as usize, SeqCst);
    }
}

#[repr(C)]
pub struct ExceptionStackFrame {
    pub instruction_pointer: u64,
    pub code_segment: u64,
    pub cpu_flags: u64,
    pub stack_pointer: u64,
    pub stack_segment: u64,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum InterruptVector {
    PageFault = 14,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) struct PageFaultVector(InterruptVector);

impl PageFaultVector {
    fn new() -> Self {
        PageFaultVector(InterruptVector::PageFault)
    }
}
impl Default for PageFaultVector {
    fn default() -> Self {
        PageFaultVector::new()
    }
}

#[derive(Copy, Clone)]
struct HandlerAddress(u64);

#[derive(Copy, Clone)]
pub(crate) enum InterruptHandler {
    PageFaultHandler(unsafe extern "C" fn(), PageFaultVector),
    Unknown(u64),
}

impl PartialEq for InterruptHandler {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                InterruptHandler::PageFaultHandler(handler, vector),
                InterruptHandler::PageFaultHandler(other_handler, other_vector),
            ) => {
                handler as *const _ as u64 == other_handler as *const _ as u64
                    && vector == other_vector
            }
            (InterruptHandler::Unknown(address), InterruptHandler::Unknown(other_address)) => {
                address == other_address
            }
            _ => false,
        }
    }
}

impl InterruptHandler {
    fn handler_address(&self) -> HandlerAddress {
        match self {
            InterruptHandler::PageFaultHandler(handler, _) => unsafe {
                *(handler as *const _ as *const HandlerAddress)
            },
            InterruptHandler::Unknown(address) => HandlerAddress(*address),
        }
    }

    fn vector(&self) -> InterruptVector {
        match self {
            InterruptHandler::PageFaultHandler(_, vector) => vector.0,
            InterruptHandler::Unknown(_) => panic!("Unknown interrupt handler"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SegmentTable {
    original_base: AtomicU64,
    base: AtomicU64,
    limit: u16,
}

/// Generic Segment Table Format
#[repr(C, packed(1))]
#[derive(Debug)]
pub(crate) struct SegmentTableRaw {
    pub(crate) limit: u16,
    pub(crate) base: u64,
}

impl SegmentTable {
    fn replace_interrupt_handler(&self, handler: InterruptHandler, vector: u64) {
        // Get the address of the IDT entry we need to replace based on the interrupt vector
        // from the provided InterruptHandler
        let idt_entry = self.get_idt_entry_for_vector(vector);

        // Replace the handler address in the IDT entry with the provided handler address
        idt_entry.replace_handler_address(&handler.handler_address());
    }

    fn get_idt_entry_for_vector(&self, vector: u64) -> Arc<IdtEntry64> {
        // Calculate the address of the IDT entry for the provided interrupt vector
        // by multiplying the vector by the size of an IdtEntry64
        let idt_base = self.base.load(SeqCst) as *mut IdtEntry64Raw;
        let idt_target_entry = unsafe { idt_base.add(vector as usize) };
        // calculate the last valid entry to the IDT based on the IDT limit
        let idt_last_entry =
            unsafe { (idt_base as *mut u8).add(self.limit as usize) } as *mut IdtEntry64Raw;
        // Ensure the target entry is within the IDT limits
        if idt_target_entry > idt_last_entry {
            panic!("IDT entry for vector {} is out of bounds", vector as usize);
        } else {
            let new_entry = Arc::new(IdtEntry64 {
                raw_entry: InterruptLock::new(idt_target_entry),
                vector,
            });

            new_entry
        }
    }
}

#[inline]
pub(crate) fn idt() -> Arc<SegmentTable> {
    let mut table = SegmentTableRaw { base: 0, limit: 0 };
    unsafe {
        asm!("sidt [{}]", in(reg) &mut table);
    }

    if let Some(cached_idt) = unsafe { &CACHED_IDT } {
        // If we find an existing entry with the same original base, return it.
        // We check this as we may be executing on different cores, and each core has its
        // own IDT.
        for entry in cached_idt.iter() {
            if entry.original_base.load(SeqCst) == table.base {
                return entry.clone();
            }
        }
    }
    // No match, create a new entry
    let seg = SegmentTable {
        original_base: AtomicU64::new(table.base),
        base: AtomicU64::new(table.base),
        limit: table.limit,
    };

    unsafe {
        // Add the entry to the global cache
        let arc_entry = Arc::new(seg);
        if let Some(cached_idt) = &mut CACHED_IDT {
            cached_idt.push(arc_entry.clone());
        } else {
            CACHED_IDT = Some(vec![arc_entry.clone()]);
        }

        arc_entry
    }
}

pub(crate) struct PageFaultInterruptHandlerManager {
    current_handler_address: InterruptHandler,
    current_vector: u64,
    previous_handler_address: Option<u64>,
    mdl: MyMDL,
    pub(crate) core_id: u64,
}

impl PageFaultInterruptHandlerManager {
    pub(crate) fn new(mdl: MyMDL, core: u64) -> Self {
        // Get the address of the current interrupt handler by reading it from the IDT
        let current_handler_idt = idt().get_idt_entry_for_vector(InterruptVector::PageFault as u64);
        // Construct the address of the entry
        let current_handler_address = unsafe {
            let raw_entry = current_handler_idt.raw_entry.lock();
            let offset_1 = (*(*raw_entry)).offset_1 as u64;
            let offset_2 = (*(*raw_entry)).offset_2 as u64;
            let offset_3 = (*(*raw_entry)).offset_3 as u64;
            HandlerAddress(offset_1 | (offset_2 << 16) | (offset_3 << 32))
        };

        // Return the manager
        PageFaultInterruptHandlerManager {
            current_handler_address: InterruptHandler::Unknown(current_handler_address.0),
            current_vector: InterruptVector::PageFault as u64,
            previous_handler_address: None,
            mdl,
            core_id: core,
        }
    }

    pub(crate) fn install_interrupt_handler(&mut self) {
        unsafe {
            asm!("int3");
        }
        let handler =
            InterruptHandler::PageFaultHandler(page_fault_handler, PageFaultVector::new());
        // Only replace the handler if it's different from the current handler
        if self.current_handler_address != handler {
            // Set previous
            self.previous_handler_address = Some(self.current_handler_address.handler_address().0);
            // Replace the current handler with the new handler
            let idt = idt();

            idt.replace_interrupt_handler(handler, self.current_vector);
            // Update the current handler address
            self.current_handler_address = handler;
        } else {
            panic!("Handler already installed");
        }
    }

    pub(crate) fn restore_interrupt_handler(&mut self) {
        if let Some(previous_handler_address) = self.previous_handler_address {
            let previous_handler = InterruptHandler::Unknown(previous_handler_address);
            let idt = idt();
            idt.replace_interrupt_handler(previous_handler, self.current_vector);
            self.current_handler_address = previous_handler;
            self.previous_handler_address = None;
            PAGE_FAULT_HIT.store(false, SeqCst);
        } else {
            unimplemented!();
        }
    }

    pub(crate) fn page_in_idt(&self) {
        let idt = idt();
        let idt_base = idt.base.load(SeqCst) as *mut IdtEntry64Raw;
        let idt_last_entry = unsafe { (idt_base as *mut u8).add(idt.limit as usize) };

        for entry in ((idt_base as u64)..(idt_last_entry as u64))
            .step_by(core::mem::size_of::<IdtEntry64Raw>())
        {
            let entry = entry as *const IdtEntry64Raw;
            let res = unsafe { core::ptr::read_volatile(entry) };
            black_box(res);
        }
    }
}

pub(crate) fn pagein_unprotect_idt() -> MyMDL {
    // Get the IDT and read every entry up to the limit to ensure they are paged in
    let idt = idt();
    let idt_base = idt.base.load(SeqCst) as *mut IdtEntry64Raw;
    unsafe {
        // Get an MDL that describes the entire IDT table
        let mdl = build_mdl(idt_base as u64, idt.limit as u64).unwrap();
        // Mark the entire MDL as RWX
        make_mdl_pages_writeable(&mdl);

        // Modify the base with the one from our MDL
        idt.base.store(mdl.mapped_base, SeqCst);
        let idt_base = idt.base.load(SeqCst) as *mut IdtEntry64Raw;
        let idt_last_entry = (idt_base as *mut u8).add(idt.limit as usize);

        for entry in ((idt_base as u64)..(idt_last_entry as u64))
            .step_by(core::mem::size_of::<IdtEntry64Raw>())
        {
            let entry = entry as *const IdtEntry64Raw;
            let res = core::ptr::read_volatile(entry);
            black_box(res);
        }

        mdl
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_probing_address() -> u64 {
    return PROBING_ADDRESS.load(SeqCst);
}

#[no_mangle]
pub unsafe extern "C" fn get_junk_pointer() -> *mut u64 {
    addr_of_mut!(JUNK)
}

#[no_mangle]
pub unsafe extern "C" fn set_page_fault_hit() {
    PAGE_FAULT_HIT.store(true, SeqCst);
}

#[no_mangle]
pub unsafe extern "C" fn get_previous_handler() -> u64 {
    return PREVIOUS_PAGE_FAULT_HANDLER.load(SeqCst) as u64;
}

// global_asm block of our page fault handler
global_asm! {
    r#"
    .section .text
    .align 16
    .extern get_probing_address
    .extern get_previous_handler
    .extern set_page_fault_hit
    .global page_fault_handler
    page_fault_handler:
        // Check if the faulted address matches our global probing address
        push rax // Original rax
        pushfq // Original rflags
        push rcx // Original rcx
        push rdx // Original rdx
        push r8 // Original r8
        push r9 // Original r9
        push r10 // Original r10
        push r11 // Original r11
        // backup XMM0-XMM5
         sub    rsp, 16
        movdqu [rsp], xmm0
        sub   rsp, 16
        movdqu [rsp], xmm1
        sub   rsp, 16
        movdqu [rsp], xmm2
        sub   rsp, 16
        movdqu [rsp], xmm3
        sub   rsp, 16
        movdqu [rsp], xmm4
        sub   rsp, 16
        movdqu [rsp], xmm5
        call get_previous_handler
        push rax // get_previous_handler result
        call get_probing_address
        // Check if the address is a match, if not then jmp to the previous handler
        // If so, then spinloop for now
        push rdx
        mov rdx, cr2
        cmp rax, rdx
        pop rdx
        jne .Lprevious_handler
        .Lprobed_address:
            call get_junk_pointer
            mov rdx, rax
            push rdx // save rdx (junk pointer)
            call set_page_fault_hit
            pop rdx // restore junk pointer
            // Restore the previous handler
            pop rax // pop the previous handler from stack
            // Restore all saved registers except rax
            movdqu xmm5, [rsp]
            add    rsp, 16
            movdqu xmm4, [rsp]
            add    rsp, 16
            movdqu xmm3, [rsp]
            add    rsp, 16
            movdqu xmm2, [rsp]
            add    rsp, 16
            movdqu xmm1, [rsp]
            add    rsp, 16
            movdqu xmm0, [rsp]
            add    rsp, 16
            pop r11
            pop r10
            pop r9
            pop r8
            // Skip over rdx, as we've modified it
            add rsp, 8
            pop rcx
            popfq
            pop rax // restore rax
            // "pop" off the error code
            add rsp, 8
            iretq
        .Lprevious_handler:
            // Restore the previous handler
            pop rax // pop the previous handler from stack
            // Restore all saved registers except rax
            movdqu xmm5, [rsp]
            add    rsp, 16
            movdqu xmm4, [rsp]
            add    rsp, 16
            movdqu xmm3, [rsp]
            add    rsp, 16
            movdqu xmm2, [rsp]
            add    rsp, 16
            movdqu xmm1, [rsp]
            add    rsp, 16
            movdqu xmm0, [rsp]
            add    rsp, 16
            pop r11
            pop r10
            pop r9
            pop r8
            pop rdx
            pop rcx
            popfq
            // Enter the previous handler
            call rax
            // Restore rax
            pop rax
            // return
            ret
            // mov rax into -8 of the current stack pointer
            //mov QWORD PTR [rsp - 16], rax
            // Restore rax
            //pop rax
            //jmp [rsp - 24]
    "#
}
