use core::arch::asm;

pub unsafe fn rdtsc() -> u64 {
    let high_bits: u32;
    let low_bits: u32;
    asm!("rdtsc", out("edx") high_bits, out("eax") low_bits);
    ((high_bits as u64) << 32) | low_bits as u64
}
