use std::marker::PhantomData;

use clap::Parser;
use clap_num::maybe_hex;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE},
    Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING},
};

pub mod uni;

// Shared types and constants between the kernel driver and user-mode application
#[path = "..\\..\\read_write_driver\\src\\shared.rs"]
pub mod shared;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Target PID to write into
    #[arg(short, long)]
    pid: u32,

    // Address to write into, may be in decimal or hex (when prefixed with 0x)
    #[arg(short, long, value_parser=maybe_hex::<usize>)]
    address: usize,
}

// Path to our kernel device
const DEVICE_PATH: &str = "\\\\.\\ReadWriteDevice";

fn main() {
    let args = Args::parse();
    // Hardcoded bytes we'll write into the target process as a test. This may be replaced with a dynamic buffer.
    let buffer = [0x01, 0x03, 0x03, 0x07];
    // Send the IOCTL request to the kernel device to write the buffer into the target process at the specified address
    write_ioctl_buffer(args.pid, args.address, &buffer);
}

/// Write the bytes from `buffer` into the target process with PID `pid` at the address `address`, using our kernel device.
fn write_ioctl_buffer(pid: u32, address: usize, buffer: &[u8]) {
    // Create a file handle to the device,
    let device_path = uni::owned_string_from_str(DEVICE_PATH);
    let device_handle = unsafe {
        CreateFileW(
            device_path.as_pcwstr(),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .unwrap()
    };
    // Create the IOCTL request
    // Determine size of the entire request, which is the size of the header plus the size of the dynamic buffer
    let req_size = core::mem::size_of::<shared::ReadWriteIoctl>() + buffer.len();
    // Create a new dynamic-sized buffer to hold the request
    let mut req_buffer: VLS<shared::ReadWriteIoctl> = VLS::new(req_size);
    unsafe {
        // Get a mutable reference to the request buffer for initialization
        let req = req_buffer.as_mut();
        // Write the header of the request
        *req = shared::ReadWriteIoctl {
            header: shared::ReadWriteIoctlHeader {
                target_pid: pid,
                address,
                buffer_len: buffer.len(),
            },
            buffer: [0; 0],
        };
        // Copy our dynamic buffer into the request from the location of the `buffer` field, this initializes the buffer in our ReadWriteIoctl struct
        std::ptr::copy_nonoverlapping(buffer.as_ptr(), (*req).buffer.as_mut_ptr(), buffer.len());
    }
    // Send the ioctl request and ensure it was successful (or panic if it wasn't)
    let mut bytes_written = 0;
    unsafe {
        DeviceIoControl(
            device_handle,
            shared::IOCTL_REQUEST,
            Some(req_buffer.as_mut() as *mut _ as _),
            req_size as u32,
            None,
            0,
            Some(&mut bytes_written),
            None,
        )
        .unwrap();
    }
}

/// Variable-length buffer of dynamic type T, allows allocating a dynamic-sized buffer and treating it as a type T
#[derive(Default)]
pub struct VLS<T> {
    v: Vec<u8>,
    _phantom: PhantomData<T>,
}

// Implement deref and deref_mut to allow treating the VLS as a type T
impl<T> core::ops::Deref for VLS<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { core::mem::transmute(self.v.as_ptr()) }
    }
}

impl<T> core::ops::DerefMut for VLS<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { core::mem::transmute(self.v.as_mut_ptr()) }
    }
}

// If T is Copy, we can implement From<T> for VLS<T> to allow creating a VLS from a value of type T
impl<T: Copy> From<T> for VLS<T> {
    fn from(val: T) -> Self {
        let mut ret = Self::new(core::mem::size_of_val(&val));
        ret.as_slice_mut()[0] = val;
        ret
    }
}

impl<T> VLS<T> {
    /// Create a VLS with a specified byte size.
    pub fn new(size: usize) -> Self {
        let v = vec![0u8; size];
        Self {
            v,
            _phantom: PhantomData::default(),
        }
    }

    /// Return an array slice of type T, guaranteed to not overflow the bounds
    /// of the allocated data
    pub fn as_slice(&self) -> &[T] {
        unsafe {
            core::slice::from_raw_parts(
                self.v.as_ptr() as *const T,
                self.v.len() / core::mem::size_of::<T>(),
            )
        }
    }

    /// Return a mutable array slice of type T, guaranteed to not overflow the
    /// bounds of the allocated data
    pub fn as_slice_mut(&mut self) -> &mut [T] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self.v.as_mut_ptr() as *mut T,
                self.v.len() / core::mem::size_of::<T>(),
            )
        }
    }

    /// Returns a raw mut pointer to T
    pub fn as_mut(&mut self) -> *mut T {
        self.v.as_mut_ptr() as *mut T
    }

    /// Returns a byte slice of the underlying data
    pub fn as_bytes(&self) -> &[u8] {
        &self.v
    }
}
