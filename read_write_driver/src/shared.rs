/// IOCTL code for the ReadWriteIoctl request. Uses METHOD_BUFFERED and FILE_ANY_ACCESS.
pub(crate) const IOCTL_REQUEST: u32 = 0x222004;

/// Struct to be used as the input buffer for the IOCTL_REQUEST command.
/// Specifies the target process ID, the address to read/write, and the buffer to read/write.
/// Comprised of a ReadWriteIoctlHeader and a dynamic-length buffer (size provided by ReadWriteIoctlHeader.buffer_len).
#[repr(C)]
pub(crate) struct ReadWriteIoctl {
    pub(crate) header: ReadWriteIoctlHeader,
    pub(crate) buffer: [u8; 0],
}

/// Header portion of the ReadWriteIoctl struct. Contains the target process ID, the address to read/write, and the buffer length.
#[repr(C)]
pub(crate) struct ReadWriteIoctlHeader {
    pub(crate) target_pid: u32,
    pub(crate) address: usize,
    pub(crate) buffer_len: usize,
}
