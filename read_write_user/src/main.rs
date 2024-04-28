use anyhow::Context;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::str::FromStr;

use crate::shared::IoctlSymbolOffsets;
use anyhow::Error;
use clap::Parser;
use clap_num::maybe_hex;
use pdb::{FallibleIterator, RawString};
use pdblister::symsrv::SymFileInfo;
use pdblister::{connect_servers, get_pdb, ManifestEntry};
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

    // Determines if we download and parse NT symbols to resolve offsets for the driver
    #[arg(short, long)]
    use_symbols: bool,
}

// Path to our kernel device
const DEVICE_PATH: &str = "\\\\.\\ReadWriteDevice";

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // Hardcoded bytes we'll write into the target process as a test. This may be replaced with a dynamic buffer.
    let buffer = [0x01, 0x03, 0x03, 0x07];
    // Send the IOCTL request to the kernel device to write the buffer into the target process at the specified address
    write_ioctl_buffer(&args, &buffer).await;
}

async fn get_nt_symbols() -> Result<shared::IoctlSymbolOffsets, anyhow::Error> {
    let filepath = "C:\\Windows\\System32\\ntoskrnl.exe";
    // Get env var NT_SYMBOL_PATH if it exists, otherwise hardcode https://msdl.microsoft.com/download/symbols
    let sym_path = match std::env::var("_NT_SYMBOL_PATH") {
        Ok(val) => val,
        Err(_) => "SRV*https://msdl.microsoft.com/download/symbols".to_string(),
    };
    let result: Result<(&'static str, PathBuf), anyhow::Error> = async {
        let servers = connect_servers(&sym_path)?;

        // Resolve the PDB for the executable specified.
        let e = ManifestEntry::from_str(
            &get_pdb((&filepath).as_ref()).context("failed to resolve PDB hash")?,
        )
        .unwrap();
        let info = SymFileInfo::RawHash(e.hash);

        for srv in servers.iter() {
            let (message, path) = {
                if let Some(p) = srv.find_file(&e.name, &info) {
                    ("file already cached", p)
                } else {
                    let path = srv
                        .download_file(&e.name, &info)
                        .await
                        .context("failed to download PDB")?;

                    ("file successfully downloaded", path)
                }
            };

            return Ok((message, path));
        }

        anyhow::bail!("no server returned the PDB file")
    }
    .await;

    match result {
        Ok((_message, path)) => {
            let mut va_space_deleted = None;
            let mut directory_table_base = None;
            let file = std::fs::File::open(path)?;
            let mut pdb = pdb::PDB::open(file)?;

            let type_information = pdb.type_information()?;
            let mut type_finder = type_information.finder();
            let mut iter = type_information.iter();
            'loop1: while let Some(typ) = iter.next()? {
                // build the type finder as we go
                type_finder.update(&iter);

                // parse the type record
                match typ.parse() {
                    Ok(pdb::TypeData::Class(pdb::ClassType {
                        name: _,
                        properties: _,
                        fields: Some(fields),
                        ..
                    })) => {
                        // this Type describes a class-like type with fields
                        // `fields` is a TypeIndex which refers to a FieldList
                        // To find information about the fields, find and parse that Type
                        match type_finder.find(fields)?.parse()? {
                            pdb::TypeData::FieldList(list) => {
                                // `fields` is a Vec<TypeData>
                                for field in list.fields {
                                    if let pdb::TypeData::Member(member) = field {
                                        if member.name == RawString::from("DirectoryTableBase") {
                                            directory_table_base = Some(member.offset);
                                            if va_space_deleted.is_some() {
                                                break 'loop1;
                                            }
                                        } else if member.name == RawString::from("VaSpaceDeleted") {
                                            va_space_deleted = Some(member.offset);
                                            if directory_table_base.is_some() {
                                                break 'loop1;
                                            }
                                        }
                                    } else {
                                        // handle member functions, nested types, etc.
                                    }
                                }

                                if let Some(_more_fields) = list.continuation {
                                    // A FieldList can be split across multiple records
                                    // TODO: follow `more_fields` and handle the next FieldList
                                }
                            }
                            _ => {}
                        }
                    }
                    Ok(_) => {
                        // ignore everything that's not a class-like type
                    }
                    Err(pdb::Error::UnimplementedTypeKind(_)) => {
                        // found an unhandled type record
                        // this probably isn't fatal in most use cases
                    }
                    Err(e) => {
                        // other error, probably is worth failing
                        return Err(Error::from(e));
                    }
                }
            }

            if let (Some(va_space_deleted), Some(directory_table_base)) =
                (va_space_deleted, directory_table_base)
            {
                return Ok(shared::IoctlSymbolOffsets {
                    va_space_deleted: Some(va_space_deleted as usize),
                    directory_table_base: Some(directory_table_base as usize),
                });
            } else {
                anyhow::bail!("Failed to find required symbols");
            }
        }
        Err(e) => {
            return Err(e);
        }
    }
}

/// Write the bytes from `buffer` into the target process with PID `pid` at the address `address`, using our kernel device.
async fn write_ioctl_buffer(args: &Args, buffer: &[u8]) {
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
    let symbols = match args.use_symbols {
        true => {
            // Panic if we fail to get the symbols when requested
            get_nt_symbols().await.unwrap()
        }
        false => IoctlSymbolOffsets {
            va_space_deleted: None,
            directory_table_base: None,
        },
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
                target_pid: args.pid,
                address: args.address,
                symbols: symbols,
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

// tests
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sym() {
        let syms = get_nt_symbols().await.unwrap();
        assert!(syms.va_space_deleted.is_some());
        assert!(syms.directory_table_base.is_some());
        println!("Symbols: {:#x?}", syms);
    }
}
