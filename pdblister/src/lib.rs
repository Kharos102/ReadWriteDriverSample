//! This is a tiny project to be a quick alternative to symchk for generating
//! manifests. This mimics symchk of the form `symchk /om manifest /r <path>`
//! but only looks for MZ/PE files.
//!
//! Due to symchk doing some weird things it can often crash or get stuck in
//! infinite loops. Thus this is a stricter (and much faster) alternative.
//!
//! The output manifest is compatible with symchk and thus symchk is currently
//! used for the actual download. To download symbols after this manifest
//! has been generated use `symchk /im manifest /s <symbol path>`
#![forbid(unsafe_code)]

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{MultiProgress, ProgressStyle};
use symsrv::{SymSrvList, SymSrvSpec};

use std::io::SeekFrom;
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use futures::{stream, Stream, StreamExt};
use indicatif::ProgressBar;
use tokio::{
    fs::{self, DirEntry},
    io::AsyncWriteExt,
};

use symsrv::{nonblocking::SymSrv, DownloadError, DownloadStatus, SymFileInfo};

pub mod pe;
#[allow(dead_code)]
pub mod symsrv;

#[derive(Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum MessageFormat {
    Human,
    Json,
}

/// Given a `path`, return a stream of all the files recursively found from
/// that path.
pub fn recursive_listdir(
    path: impl Into<PathBuf>,
) -> impl Stream<Item = io::Result<DirEntry>> + Send + 'static {
    async fn one_level(path: PathBuf, to_visit: &mut Vec<PathBuf>) -> io::Result<Vec<DirEntry>> {
        let mut dir = fs::read_dir(path).await?;
        let mut files = Vec::new();

        while let Some(child) = dir.next_entry().await? {
            if child.metadata().await?.is_dir() {
                to_visit.push(child.path());
            } else {
                files.push(child)
            }
        }

        Ok(files)
    }

    stream::unfold(vec![path.into()], |mut to_visit| async {
        let path = to_visit.pop()?;
        let file_stream = match one_level(path, &mut to_visit).await {
            Ok(files) => stream::iter(files).map(Ok).left_stream(),
            Err(e) => stream::once(async { Err(e) }).right_stream(),
        };

        Some((file_stream, to_visit))
    })
    .flatten()
}

pub fn get_pdb_path<P: AsRef<Path>>(pdbname: P) -> anyhow::Result<PathBuf> {
    use pdb::PDB;

    let file_name = Path::new(
        pdbname
            .as_ref()
            .file_name()
            .context("no filename component on path")?,
    );

    let f = std::fs::File::open(&pdbname).context("failed to open file")?;
    let mut pdb = PDB::open(f).context("failed to parse PDB")?;

    // Query the GUID and age.
    let pdbi = pdb
        .pdb_information()
        .context("failed to find PDB information stream")?;
    let dbi = pdb
        .debug_information()
        .context("failed to find DBI stream")?;

    let guid = pdbi.guid;
    let age = dbi.age().unwrap_or(pdbi.age);

    Ok(file_name
        .join(format!("{:032X}{:x}", guid.as_u128(), age))
        .join(file_name))
}

pub fn get_file_path(filename: &Path) -> anyhow::Result<String> {
    let (_, _, pe_header, image_size, _) = pe::parse_pe(filename)?;

    let filename = filename
        .file_name()
        .context("Failed to get file name")?
        .to_str()
        .context("Failed to convert file name")?;

    let filestr = format!(
        "{}/{:08x}{:x}/{}",
        filename,
        { pe_header.timestamp },
        image_size,
        filename
    );

    /* For hashes
    let filestr = format!("{},{:08x}{:x},1",
                          filename.file_name()
                            .unwrap().to_str().unwrap(),
                          pe_header.timestamp,
                          image_size);*/

    Ok(filestr)
}

/// Given a `filename`, attempt to parse out any mention of a PDB file in it.
///
/// This returns success if it successfully parses the MZ, PE, finds a debug
/// header, matches RSDS signature, and contains a valid reference to a PDB.
///
/// Returns a string which is the same representation you get from `symchk`
/// when outputting a manifest for the PDB "<filename>,<guid><age>,1"
pub fn get_pdb(filename: &Path) -> anyhow::Result<String> {
    let (mut fd, mz_header, pe_header, _, num_tables) = pe::parse_pe(filename)?;

    /* Load all the data directories into a vector */
    let mut data_dirs = Vec::new();
    for _ in 0..num_tables {
        let datadir: pe::ImageDataDirectory = pe::read_struct(&mut fd)?;
        data_dirs.push(datadir);
    }

    /* Debug directory is at offset 6, validate we have at least 7 entries */
    if data_dirs.len() < 7 {
        anyhow::bail!("No debug data directory");
    }

    /* Grab the debug table */
    let debug_table = data_dirs[6];
    if debug_table.vaddr == 0 || debug_table.size == 0 {
        anyhow::bail!("Debug directory not present or zero sized");
    }

    /* Validate debug table size is sane */
    let iddlen = std::mem::size_of::<pe::ImageDebugDirectory>() as u32;
    let debug_table_ents = debug_table.size / iddlen;
    if (debug_table.size % iddlen) != 0 || debug_table_ents == 0 {
        anyhow::bail!("No debug entries or not mod ImageDebugDirectory");
    }

    /* Seek to where the section table should be */
    let section_headers =
        mz_header.new_header as u64 + 0x18 + pe_header.optional_header_size as u64;
    if fd.seek(SeekFrom::Start(section_headers))? != section_headers {
        anyhow::bail!("Failed to seek to section table");
    }

    /* Parse all the sections into a vector */
    let mut sections = Vec::new();
    for _ in 0..pe_header.num_sections {
        let sechdr: pe::ImageSectionHeader = pe::read_struct(&mut fd)?;
        sections.push(sechdr);
    }

    let debug_raw_ptr = {
        /* Find the section the debug table belongs to */
        let mut debug_data = None;
        for section in &sections {
            /* We use raw_data_size instead of vsize as we are not loading the
             * file and only care about raw contents in the file.
             */
            let secrange = section.vaddr..section.vaddr + section.raw_data_size;

            /* Check if the entire debug table is contained in this sections
             * virtual address range.
             */
            if secrange.contains(&{ debug_table.vaddr })
                && secrange.contains(&(debug_table.vaddr + debug_table.size - 1))
            {
                debug_data = Some(debug_table.vaddr - section.vaddr + section.pointer_to_raw_data);
                break;
            }
        }

        match debug_data {
            Some(d) => d as u64,
            None => anyhow::bail!("Unable to find debug data"),
        }
    };

    /* Seek to where the debug directories should be */
    if fd.seek(SeekFrom::Start(debug_raw_ptr))? != debug_raw_ptr {
        anyhow::bail!("Failed to seek to debug directories");
    }

    /* Look through all debug table entries for codeview entries */
    for _ in 0..debug_table_ents {
        let de: pe::ImageDebugDirectory = pe::read_struct(&mut fd)?;

        if de.typ == pe::IMAGE_DEBUG_TYPE_CODEVIEW {
            /* Seek to where the codeview entry should be */
            let cvo = de.pointer_to_raw_data as u64;
            if fd.seek(SeekFrom::Start(cvo))? != cvo {
                anyhow::bail!("Failed to seek to codeview entry");
            }

            let cv: pe::CodeviewEntry = pe::read_struct(&mut fd)?;
            if &cv.signature != b"RSDS" {
                anyhow::bail!("No RSDS signature present in codeview ent");
            }

            /* Calculate theoretical string length based on the size of the
             * section vs the size of the header */
            let cv_strlen = de.size_of_data as usize - std::mem::size_of_val(&cv);

            /* Read in the debug path */
            let mut dpath = vec![0u8; cv_strlen];
            fd.read_exact(&mut dpath)?;

            /* PDB strings are utf8 and null terminated, find the first null
             * and we will split it there.
             */
            if let Some(null_strlen) = dpath.iter().position(|&x| x == 0) {
                let dpath = std::str::from_utf8(&dpath[..null_strlen])?;

                /* Further, since this path can be a full path, we get only
                 * the filename component of this path.
                 */
                if let Some(pdbfilename) = Path::new(dpath).file_name() {
                    /* This is the format string used by symchk.
                     * Original is in SymChkCheckFiles()
                     * "%s,%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%x,1"
                     */
                    let guidstr = format!("{},{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:x},1",
                                          pdbfilename.to_str().context("Failed to get PDB filename")?,
                                          {cv.guid_a}, {cv.guid_b}, {cv.guid_c},
                                          {cv.guid_d[0]}, {cv.guid_d[1]},
                                          {cv.guid_d[2]}, {cv.guid_d[3]},
                                          {cv.guid_d[4]}, {cv.guid_d[5]},
                                          {cv.guid_d[6]}, {cv.guid_d[7]},
                                          {cv.age});
                    return Ok(guidstr);
                } else {
                    anyhow::bail!("Could not parse file from RSDS path");
                }
            } else {
                anyhow::bail!("Failed to find null terminiator in RSDS");
            }
        }
    }

    anyhow::bail!("Failed to find RSDS codeview directory")
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    /// The PDB's name
    pub name: String,
    /// The hash plus age of the PDB
    pub hash: String,
    /// The version number (maybe?)
    version: u32,
}

impl FromStr for ManifestEntry {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let elements = s.split(',').collect::<Vec<_>>();
        if elements.len() != 3 {
            anyhow::bail!("Invalid manifest line: \"{s}\"");
        }

        Ok(Self {
            name: elements[0].to_string(),
            hash: elements[1].to_string(),
            version: u32::from_str(elements[2])?,
        })
    }
}

/// Attempt to connect to the servers described in the server string.
pub fn connect_servers(srvstr: &str) -> anyhow::Result<Box<[SymSrv]>> {
    let srvlist = SymSrvList::from_str(srvstr).context("failed to parse server list")?;

    match srvlist
        .0
        .iter()
        .map(|s| SymSrv::connect(s.clone()).map_err(|e| (s.clone(), e)))
        .collect::<Result<Vec<_>, (SymSrvSpec, anyhow::Error)>>()
    {
        Ok(srv) => Ok(srv.into_boxed_slice()),
        Err((s, e)) => Err(e.context(format!("failed to connect to server {s}"))),
    }
}

pub async fn download_manifest(srvstr: &str, files: Vec<String>) -> anyhow::Result<()> {
    let servers = connect_servers(srvstr)?;

    // http://patshaughnessy.net/2020/1/20/downloading-100000-files-using-async-rust
    // The following code is based off of the above blog post.
    let m = MultiProgress::new();

    // Create a progress bar.
    let pb = m.add(ProgressBar::new(files.len() as u64));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {wide_bar:.cyan/blue} {pos:>10}/{len:10} ({eta}) {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );

    // Set up our asynchronous code block.
    // This block will be lazily executed when something awaits on it, such as the tokio thread pool below.
    let queries = futures::stream::iter(
        // Map the files vector using a closure, such that it's converted from a Vec<String>
        // into a Vec<Result<T, E>>
        files.into_iter().map(|line| {
            // Take explicit references to a few variables and move them into the async block.
            let servers = &servers;
            let pb = pb.clone();
            let m = &m;

            async move {
                pb.inc(1);

                let e = ManifestEntry::from_str(&line).unwrap();
                let info = SymFileInfo::RawHash(e.hash);

                for srv in servers.iter() {
                    if srv.find_file(&e.name, &info).is_some() {
                        return Ok(DownloadStatus::AlreadyExists);
                    }

                    match srv.download_file_progress(&e.name, &info, m).await {
                        Ok(_) => return Ok(DownloadStatus::DownloadedOk),
                        Err(_e) => {}
                    };
                }

                Err(DownloadError::FileNotFound)
            }
        }),
    )
    .buffer_unordered(32)
    .collect::<Vec<Result<DownloadStatus, DownloadError>>>();

    // N.B: The buffer_unordered bit above allows us to feed in 64 requests at a time to tokio.
    // That way we don't exhaust system resources in the networking stack or filesystem.
    let output = queries.await;

    pb.finish();

    let mut ok = 0u64;
    let mut ok_exists = 0u64;
    let mut err = 0u64;

    // Collect output results.
    output.iter().for_each(|x| match x {
        Err(_) => {
            err += 1;
        }

        Ok(s) => match s {
            DownloadStatus::AlreadyExists => ok_exists += 1,
            DownloadStatus::DownloadedOk => ok += 1,
        },
    });

    println!("{} files failed to download", err);
    println!("{} files already downloaded", ok_exists);
    println!("{} files downloaded successfully", ok);

    Ok(())
}
