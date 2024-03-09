use core::arch::asm;
use core::cell::UnsafeCell;
use core::hint::black_box;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::SeqCst;
use iced_x86::Decoder;
use crate::mdl::{build_mdl, make_mdl_pages_writeable, MyMDL};

pub(crate) static PAGE_FAULT_HIT: AtomicBool = AtomicBool::new(false);

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
    previous_entry: Option<IdtEntry64Raw>,
}

impl IdtEntry64 {
    fn replace_handler_address(&mut self, handler: &HandlerAddress) {
        let handler_address = handler.0;
        let mut raw_entry = self.raw_entry.lock();
        // As we're making changes, backup the current entry by storing it in the previous_entry field.
        self.previous_entry = Some(unsafe { *(*raw_entry) });
        // Replace the handler address in the IDT entry with the provided handler address.
        unsafe {
            (*(*raw_entry)).offset_1 = handler_address as u16;
            (*(*raw_entry)).offset_2 = (handler_address >> 16) as u16;
            (*(*raw_entry)).offset_3 = (handler_address >> 32) as u32;
        }
    }

    fn replace_entry(&mut self, new_entry: IdtEntry64Raw) {
        // Overwrite our raw entry with the new entry
        unsafe {
            let mut current_raw_entry = self.raw_entry.lock();
            // Backup our current entry by storing it in the previous_entry field
            self.previous_entry = Some(*(*current_raw_entry));
            (*(*current_raw_entry)) = new_entry;
        }
    }

    fn restore_previous_entry(&mut self) -> bool {
        // Restore the previous entry if it exists
        if let Some(previous_entry) = self.previous_entry {
            self.replace_entry(previous_entry);
            true
        } else {
            false
        }
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

#[derive(Eq, PartialEq, Copy, Clone)]
pub(crate) enum InterruptHandler {
    PageFaultHandler(
        extern "x86-interrupt" fn(&mut ExceptionStackFrame),
        PageFaultVector,
    ),
    Unknown(u64),
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

/// Generic Segment Table Format
#[repr(C, packed(1))]
#[derive(Clone, Debug)]
pub(crate) struct SegmentTableRaw {
    pub(crate) limit: u16,
    pub(crate) base: u64,
}

impl SegmentTableRaw {
    fn replace_interrupt_handler(&mut self, handler: InterruptHandler, vector: u64) {
        // Get the address of the IDT entry we need to replace based on the interrupt vector
        // from the provided InterruptHandler
        let mut idt_entry = self.get_idt_entry_for_vector(vector);

        // Replace the handler address in the IDT entry with the provided handler address
        idt_entry.replace_handler_address(&handler.handler_address());
    }

    fn get_idt_entry_for_vector(&self, vector: u64) -> IdtEntry64 {
        // Calculate the address of the IDT entry for the provided interrupt vector
        // by multiplying the vector by the size of an IdtEntry64
        let idt_base = self.base as *mut IdtEntry64Raw;
        let idt_target_entry = unsafe { idt_base.add(vector as usize) };
        // calculate the last valid entry to the IDT based on the IDT limit
        let idt_last_entry = unsafe { (idt_base as *mut u8).add(self.limit as usize) } as *mut IdtEntry64Raw;
        // Ensure the target entry is within the IDT limits
        if idt_target_entry > idt_last_entry {
            panic!("IDT entry for vector {} is out of bounds", vector as usize);
        } else {
            // Return the address of the IDT entry
            IdtEntry64 {
                raw_entry: InterruptLock::new(idt_target_entry),
                previous_entry: None,
            }
        }
    }
}

#[inline]
pub(crate) fn idt() -> SegmentTableRaw {
    let mut table = SegmentTableRaw { base: 0, limit: 0 };
    unsafe {
        asm!("sidt [{}]", in(reg) &mut table);
    }

    table
}

pub(crate) struct PageFaultInterruptHandlerManager {
    current_handler_address: InterruptHandler,
    current_vector: u64,
    previous_handler_address: Option<u64>,
    mdl: MyMDL,
}

impl PageFaultInterruptHandlerManager {
    pub(crate) fn new(mdl: MyMDL) -> Self {
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
        }
    }

    pub(crate) fn install_interrupt_handler(&mut self) {
        let handler = InterruptHandler::PageFaultHandler(page_fault_handler, PageFaultVector::new());
        // Only replace the handler if it's different from the current handler
        if self.current_handler_address != handler {
            // Set previous
            self.previous_handler_address = Some(self.current_handler_address.handler_address().0);
            // Replace the current handler with the new handler
            let mut idt = idt();
            // Modify the base with the one from our MDL
            idt.base = self.mdl.mapped_base;
            idt.replace_interrupt_handler(handler, self.current_vector);
            // Update the current handler address
            self.current_handler_address = handler;
        }
    }

    pub(crate) fn restore_interrupt_handler(&mut self) {
        if let Some(previous_handler_address) = self.previous_handler_address {
            let previous_handler = InterruptHandler::Unknown(previous_handler_address);
            let mut idt = idt();
            idt.replace_interrupt_handler(previous_handler, self.current_vector);
            self.current_handler_address = previous_handler;
            self.previous_handler_address = None;
            PAGE_FAULT_HIT.store(false, SeqCst);
        } else {
            unimplemented!();
        }
    }

}

pub(crate) fn pagein_unprotect_idt() -> MyMDL {
    // Get the IDT and read every entry up to the limit to ensure they are paged in
    let idt = idt();
    let idt_base = idt.base as *mut IdtEntry64Raw;
    let idt_last_entry = unsafe { (idt_base as *mut u8).add(idt.limit as usize) };
    // Perform a volatile read
    unsafe {
        for entry in ((idt_base as u64)..(idt_last_entry as u64)).step_by(core::mem::size_of::<IdtEntry64Raw>()) {
            let entry = entry as *const IdtEntry64Raw;
            let res = core::ptr::read_volatile(entry);
            black_box(res);
        }
        // Get an MDL that describes the entire IDT table
        let mdl = build_mdl(idt_base as u64, idt.limit as u64).unwrap();
        // Mark the entire MDL as RWX
        make_mdl_pages_writeable(&mdl);

        mdl
    }
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: &mut ExceptionStackFrame,
) {
    // If a page fault is hit while our handler is in place, we expect the following to be true:
    // 1. The PAGE_FAULT_HIT flag is false
    // 2. The error is from supervisor mode and caused by a write
    assert_eq!(PAGE_FAULT_HIT.load(SeqCst), false);

    // Passed our checks, set the PAGE_FAULT_HIT flag to true
    PAGE_FAULT_HIT.store(true, SeqCst);

    // Assume we can read the maximum instruction length of 15 bytes from the instruction pointer
    let instruction_bytes =
        unsafe { core::slice::from_raw_parts_mut(stack_frame.instruction_pointer as *mut u8, 15) };
    let mut decoder = Decoder::with_ip(
        64,
        instruction_bytes,
        stack_frame.instruction_pointer,
        iced_x86::DecoderOptions::NONE,
    );
    // Read the instruction
    let inst = decoder.decode();
    // Get the length
    let inst_len = inst.len() as u64;
    // Update the stack frame to skip over the instruction
    unsafe {
        core::ptr::write_volatile(
            &mut stack_frame.instruction_pointer,
            stack_frame.instruction_pointer + inst_len,
        );
    }
    // Done
}
