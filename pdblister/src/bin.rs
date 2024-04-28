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
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use pdblister::symsrv::SymFileInfo;
use pdblister::{
    connect_servers, download_manifest, get_file_path, get_pdb, get_pdb_path, recursive_listdir,
    ManifestEntry, MessageFormat,
};
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tokio::fs::DirEntry;
use tokio::io::AsyncWriteExt;

/// This tool lets you quickly download PDBs from a symbol server
#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Clone, Debug)]
enum Command {
    /// Recursively searches a directory tree and generate a manifest file containing PDB hashes for all executables found
    ///
    /// This command takes in a filepath to recursively search for files that
    /// have a corresponding PDB. This creates a file which is compatible with
    /// symchk.
    ///
    /// For example `pdblister manifest C:\windows` will create `manifest`
    /// containing all of the PDB signatures for all of the files in
    /// C:\windows.
    Manifest {
        /// The root of the directory tree to search for PEs
        filepath: PathBuf,
        /// The destination manifest path
        manifest: Option<PathBuf>,
    },
    /// Downloads all the PDBs specified in the manifest file
    Download {
        /// The symbol server URL
        symsrv: String,
        /// The manifest path
        manifest: Option<PathBuf>,
    },
    /// Downloads a PDB file corresponding to a single PE file
    DownloadSingle {
        /// The symbol server URL
        symsrv: String,
        /// The PE file path
        filepath: PathBuf,
        /// The format to print the message in
        message_format: MessageFormat,
    },
    /// Recursively searches a directory tree and caches all PEs in the current directory in a symbol cache layout
    ///
    /// This command recursively walks filepath to find all PEs. Any PE file
    /// that is found is copied to the local directory 'targetpath' using the
    /// layout that symchk.exe uses to store normal files. This is used to
    /// create a store of all PEs (such as .dlls), which can be used by a
    /// kernel debugger to read otherwise paged out memory by downloading the
    /// original PE source file from this filestore.
    ///
    /// To use this filestore simply merge the contents in with a symbol
    /// store/cache path. We keep it separate in this tool just to make it
    /// easier to only get PDBs if that's all you really want.
    Filestore {
        /// The root of the directory tree to search for PEs
        filepath: PathBuf,
        /// The target directory to stash PEs in
        targetpath: PathBuf,
    },
    /// Recursively searches a directory tree and caches all PDBs in the current directory in a symbol cache layout
    ///
    /// This command recursively walks filepath to find all PDBs. Any PDB file
    /// that is found is copied to the local directory 'targetpath' using the
    /// same layout as symchk.exe. This is used to create a store of all PDBs
    /// which can be used by a kernel debugger to resolve symbols.
    ///
    /// To use this filestore simply merge the contents in with a symbol
    /// store/cache path. We keep it separate in this tool just to make it
    /// easier to only get PDBs if that's all you really want.
    Pdbstore {
        /// The root of the directory tree to search for PDBs
        filepath: PathBuf,
        /// The target directory to stash PDBs in
        targetpath: PathBuf,
    },
    /// Various information-related subcommands
    #[command(subcommand)]
    Info(InfoCommand),
}

#[derive(Subcommand, Clone, Debug)]
enum InfoCommand {
    /// Dumps out the hash of the corresponding PDB file for a PE file
    Pdbhash {
        /// The path to the PE file to dump the PDB hash for
        filepath: PathBuf,
    },
}

async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Manifest { filepath, manifest } => {
            /* List all files in the directory specified by args[2] */
            let listing: Vec<Result<DirEntry, io::Error>> =
                recursive_listdir(filepath).collect().await;

            let pb = ProgressBar::new(listing.len() as u64);

            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "[{elapsed_precise}] {wide_bar:.cyan/blue} {pos:>7}/{len:7} ({eta}) {msg}",
                    )
                    .unwrap()
                    .progress_chars("##-"),
            );

            // Map the listing into strings to write into the manifest
            let tasks: Vec<_> = listing
                .into_iter()
                .filter_map(move |e| {
                    let pb = pb.clone();

                    match e {
                        Ok(e) => Some(tokio::spawn(async move {
                            pb.inc(1);

                            match get_pdb(&e.path()) {
                                Ok(manifest_str) => Some(manifest_str),
                                Err(_) => None,
                            }
                        })),

                        Err(_) => None,
                    }
                })
                .collect();

            let manifest_path = manifest.unwrap_or(PathBuf::from("manifest"));
            let mut output_file = tokio::fs::File::create(manifest_path)
                .await
                .context("Failed to create output manifest file")?;

            for task in tasks {
                if let Some(e) = task.await.unwrap() {
                    output_file
                        .write(format!("{}\n", &e).as_bytes())
                        .await
                        .context("Failed to write to output manifest file")?;
                }
            }
        }
        Command::Download { manifest, symsrv } => {
            /* Read the entire manifest file into a string */
            let manifest_path = manifest.unwrap_or(PathBuf::from("manifest"));
            let buf = tokio::fs::read_to_string(&manifest_path)
                .await
                .context("failed to read manifest file")?;

            /* Split the file into lines and collect into a vector */
            let mut lines: Vec<String> = buf.lines().map(String::from).collect();

            /* If there is nothing to download, return out early */
            if lines.is_empty() {
                println!("Nothing to download");
                return Ok(());
            }

            println!("Original manifest has {} PDBs", lines.len());

            lines.sort();
            lines.dedup();

            println!("Deduped manifest has {} PDBs", lines.len());

            match download_manifest(&symsrv, lines).await {
                Ok(_) => println!("Success!"),
                Err(e) => println!("Failed: {:?}", e),
            }
        }
        Command::DownloadSingle {
            symsrv,
            filepath,
            message_format,
        } => {
            use serde_json::json;

            let result: Result<(&'static str, PathBuf), anyhow::Error> = async {
                let servers = connect_servers(&symsrv)?;

                // Resolve the PDB for the executable specified.
                let e = ManifestEntry::from_str(
                    &get_pdb(&filepath).context("failed to resolve PDB hash")?,
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
                Ok((message, path)) => match message_format {
                    MessageFormat::Human => {
                        println!("{}: {}", message, path.to_string_lossy())
                    }
                    MessageFormat::Json => println!(
                        "{}",
                        json!({
                            "status": "success",
                            "message": message,
                            "path": path.to_str().expect("symbol path was not valid utf-8")
                        })
                    ),
                },
                Err(e) => {
                    match message_format {
                        MessageFormat::Human => println!("operation failed: {e:?}"),
                        MessageFormat::Json => println!(
                            "{}",
                            json!({
                                "status": "failed",
                                "message": format!("{e:#}"),
                            })
                        ),
                    }
                    std::process::exit(1);
                }
            }
        }
        Command::Filestore {
            filepath,
            targetpath,
        } => {
            /* List all files in the directory specified by args[2] */
            let dir = Path::new(&filepath);
            let target = Path::new(&targetpath);
            let listing = recursive_listdir(&dir);

            listing
                .for_each(|entry| async {
                    if let Ok(e) = entry {
                        if let Ok(fsname) = get_file_path(&e.path()) {
                            let fsname = target.join(&fsname);

                            if !fsname.exists() {
                                let dir = fsname.parent().unwrap();
                                tokio::fs::create_dir_all(dir)
                                    .await
                                    .expect("Failed to create filestore directory");

                                if let Err(err) = tokio::fs::copy(&e.path(), fsname).await {
                                    println!("Failed to copy file {:?}: {err:#}", &e.path());
                                }
                            }
                        }
                    }
                })
                .await;
        }
        Command::Pdbstore {
            filepath,
            targetpath,
        } => {
            /* List all files in the directory specified by args[2] */
            let listing = recursive_listdir(&filepath);

            listing
                .for_each(|entry| async {
                    if let Ok(e) = entry {
                        if let Ok(fsname) = get_pdb_path(&e.path()) {
                            let fsname = targetpath.join(&fsname);

                            if !fsname.exists() {
                                let dir = fsname.parent().unwrap();
                                tokio::fs::create_dir_all(dir)
                                    .await
                                    .expect("Failed to create filestore directory");

                                if let Err(err) = tokio::fs::copy(&e.path(), fsname).await {
                                    println!("Failed to copy file {:?}: {err:#}", &e.path());
                                }
                            }
                        }
                    }
                })
                .await;
        }
        Command::Info(i) => match i {
            InfoCommand::Pdbhash { filepath } => {
                let pdb = get_pdb(&filepath)?;
                println!("{}", pdb);
            }
        },
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    run().await.unwrap();
}
