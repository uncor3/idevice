//! AFC (Apple File Conduit) client implementation for interacting with iOS devices.
//!
//! This module provides functionality to interact with the file system of iOS devices
//! through the AFC protocol.

use std::collections::{HashMap, HashSet, VecDeque};

use errors::AfcError;
use opcode::{AfcFopenMode, AfcOpcode};
use packet::{AfcPacket, AfcPacketHeader};
use tracing::warn;

use crate::{
    Idevice, IdeviceError, IdeviceService,
    afc::file::{FileDescriptor, OwnedFileDescriptor},
    lockdown::LockdownClient,
    obf,
};

pub mod errors;
pub mod file;
mod inner_file;
mod inner_file_impl_macro;
pub mod opcode;
pub mod packet;

/// The magic number used in AFC protocol communications
pub const MAGIC: u64 = 0x4141504c36414643;

/// Client for interacting with the AFC service on iOS devices
#[derive(Debug)]
pub struct AfcClient {
    /// The underlying iDevice connection
    pub idevice: Idevice,
    package_number: u64,
}

/// Information about a file on the device
#[derive(Clone, Debug)]
pub struct FileInfo {
    /// Size of the file in bytes
    pub size: usize,
    /// Number of blocks allocated for the file
    pub blocks: usize,
    /// Creation timestamp of the file
    pub creation: chrono::NaiveDateTime,
    /// Last modification timestamp of the file
    pub modified: chrono::NaiveDateTime,
    /// Number of hard links to the file
    pub st_nlink: String,
    /// File type (e.g., "S_IFREG" for regular file)
    pub st_ifmt: String,
    /// Target path if this is a symbolic link
    pub st_link_target: Option<String>,
}

/// Metadata for an AFC path after resolving all symbolic links in the path.
///
/// Unlike [`AfcClient::get_file_info`], this resolves symbolic links in both
/// intermediate path components and the final component. `requested_path`
/// preserves the caller's input, while `resolved_path` is the normalized,
/// absolute path of the final target in the current AFC service namespace.
#[derive(Clone, Debug)]
pub struct ResolvedFileInfo {
    /// Path supplied by the caller.
    pub requested_path: String,
    /// Normalized final target path after resolving symbolic links.
    pub resolved_path: String,
    /// Metadata for the final target.
    pub info: FileInfo,
}

/// Information about the device's filesystem
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    /// Device model identifier
    pub model: String,
    /// Total storage capacity in bytes
    pub total_bytes: usize,
    /// Free storage space in bytes
    pub free_bytes: usize,
    /// Filesystem block size in bytes
    pub block_size: usize,
}

impl IdeviceService for AfcClient {
    fn service_name() -> std::borrow::Cow<'static, str> {
        obf!("com.apple.afc")
    }

    async fn from_stream(idevice: Idevice) -> Result<Self, IdeviceError> {
        Ok(Self {
            idevice,
            package_number: 0,
        })
    }
}

impl AfcClient {
    /// Creates a new AFC client from an existing iDevice connection
    ///
    /// # Arguments
    /// * `idevice` - An established iDevice connection
    pub fn new(idevice: Idevice) -> Self {
        Self {
            idevice,
            package_number: 0,
        }
    }

    /// Connects to afc2 from a provider
    pub async fn new_afc2(
        provider: &dyn crate::provider::IdeviceProvider,
    ) -> Result<Self, IdeviceError> {
        let mut lockdown = LockdownClient::connect(provider).await?;

        let legacy = lockdown
            .start_session(&provider.get_pairing_file().await?)
            .await?;

        let (port, ssl) = lockdown.start_service(obf!("com.apple.afc2")).await?;

        let mut idevice = provider.connect(port).await?;
        if ssl {
            idevice
                .start_session(&provider.get_pairing_file().await?, legacy)
                .await?;
        }

        Self::from_stream(idevice).await
    }

    /// Lists the contents of a directory on the device
    ///
    /// # Arguments
    /// * `path` - Path to the directory to list
    ///
    /// # Returns
    /// A vector of file/directory names in the specified directory
    pub async fn list_dir(&mut self, path: impl Into<String>) -> Result<Vec<String>, IdeviceError> {
        let path = path.into();
        let header_payload = path.as_bytes().to_vec();
        let header_len = header_payload.len() as u64 + AfcPacketHeader::LEN;

        let header = AfcPacketHeader {
            magic: MAGIC,
            entire_len: header_len, // it's the same since the payload is empty for this
            header_payload_len: header_len,
            packet_num: self.package_number,
            operation: AfcOpcode::ReadDir,
        };
        self.package_number += 1;

        let packet = AfcPacket {
            header,
            header_payload,
            payload: Vec::new(),
        };

        self.send(packet).await?;
        let res = self.read().await?;

        let strings: Vec<String> = res
            .payload
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        Ok(strings)
    }

    /// Creates a new directory on the device
    ///
    /// # Arguments
    /// * `path` - Path of the directory to create
    pub async fn mk_dir(&mut self, path: impl Into<String>) -> Result<(), IdeviceError> {
        let path = path.into();
        let header_payload = path.as_bytes().to_vec();
        let header_len = header_payload.len() as u64 + AfcPacketHeader::LEN;

        let header = AfcPacketHeader {
            magic: MAGIC,
            entire_len: header_len, // it's the same since the payload is empty for this
            header_payload_len: header_len,
            packet_num: self.package_number,
            operation: AfcOpcode::MakeDir,
        };
        self.package_number += 1;

        let packet = AfcPacket {
            header,
            header_payload,
            payload: Vec::new(),
        };

        self.send(packet).await?;
        self.read().await?; // read a response to check for errors

        Ok(())
    }

    /// Retrieves information about a file or directory
    ///
    /// # Arguments
    /// * `path` - Path to the file or directory
    ///
    /// # Returns
    /// A `FileInfo` struct containing information about the file
    pub async fn get_file_info(
        &mut self,
        path: impl Into<String>,
    ) -> Result<FileInfo, IdeviceError> {
        let path = path.into();
        let header_payload = path.as_bytes().to_vec();
        let header_len = header_payload.len() as u64 + AfcPacketHeader::LEN;

        let header = AfcPacketHeader {
            magic: MAGIC,
            entire_len: header_len, // it's the same since the payload is empty for this
            header_payload_len: header_len,
            packet_num: self.package_number,
            operation: AfcOpcode::GetFileInfo,
        };
        self.package_number += 1;

        let packet = AfcPacket {
            header,
            header_payload,
            payload: Vec::new(),
        };

        self.send(packet).await?;
        let res = self.read().await?;

        let strings: Vec<String> = res
            .payload
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        let mut kvs: HashMap<String, String> = strings
            .chunks_exact(2)
            .map(|chunk| (chunk[0].clone(), chunk[1].clone()))
            .collect();

        let size = kvs
            .remove("st_size")
            .and_then(|x| x.parse::<usize>().ok())
            .ok_or(AfcError::MissingAttribute)?;
        let blocks = kvs
            .remove("st_blocks")
            .and_then(|x| x.parse::<usize>().ok())
            .ok_or(AfcError::MissingAttribute)?;

        let creation = kvs
            .remove("st_birthtime")
            .and_then(|x| x.parse::<i64>().ok())
            .ok_or(AfcError::MissingAttribute)?;
        let creation = chrono::DateTime::from_timestamp_nanos(creation).naive_local();

        let modified = kvs
            .remove("st_mtime")
            .and_then(|x| x.parse::<i64>().ok())
            .ok_or(AfcError::MissingAttribute)?;
        let modified = chrono::DateTime::from_timestamp_nanos(modified).naive_local();

        let st_nlink = kvs.remove("st_nlink").ok_or(AfcError::MissingAttribute)?;
        let st_ifmt = kvs.remove("st_ifmt").ok_or(AfcError::MissingAttribute)?;
        // for some reason st_link_target was being used; AFC reports this field as LinkTarget.
        let st_link_target = kvs
            .remove("LinkTarget")
            .or_else(|| kvs.remove("st_link_target"));

        if !kvs.is_empty() {
            warn!("File info kvs not empty: {kvs:?}");
        }

        Ok(FileInfo {
            size,
            blocks,
            creation,
            modified,
            st_nlink,
            st_ifmt,
            st_link_target,
        })
    }

    /// Resolves symbolic links in an AFC path and returns the normalized final path.
    ///
    /// Relative symbolic-link targets are interpreted relative to the directory
    /// containing the link. Absolute targets are interpreted from the root of
    /// the current AFC service namespace. Resolution is limited to 40 symbolic
    /// links and fails if a cycle is detected or a link has no target.
    pub async fn resolve_path(&mut self, path: impl Into<String>) -> Result<String, IdeviceError> {
        const MAX_SYMLINKS: usize = 40;

        let requested_path = path.into();
        let mut pending = normalize_afc_path_components(&[], &requested_path)?;
        let mut resolved = Vec::new();
        let mut visited_links = HashSet::new();
        let mut followed_links = 0_usize;

        while let Some(component) = pending.pop_front() {
            let candidate = afc_path_from_components(
                resolved
                    .iter()
                    .map(String::as_str)
                    .chain(std::iter::once(component.as_str())),
            );
            let info = self.get_file_info(&candidate).await?;

            if info.st_ifmt != "S_IFLNK" {
                resolved.push(component);
                continue;
            }

            followed_links += 1;
            if followed_links > MAX_SYMLINKS {
                return Err(IdeviceError::UnexpectedResponse(format!(
                    "AFC symbolic-link resolution exceeded {MAX_SYMLINKS} links for {requested_path}"
                )));
            }
            if !visited_links.insert(candidate.clone()) {
                return Err(IdeviceError::UnexpectedResponse(format!(
                    "AFC symbolic-link cycle detected at {candidate}"
                )));
            }

            let target = info.st_link_target.ok_or_else(|| {
                IdeviceError::UnexpectedResponse(format!(
                    "AFC symbolic link {candidate} has no st_link_target"
                ))
            })?;
            let base = if target.starts_with('/') {
                &[][..]
            } else {
                resolved.as_slice()
            };
            let mut expanded = normalize_afc_path_components(base, &target)?;
            expanded.extend(pending);
            pending = expanded;
            resolved.clear();
        }

        Ok(afc_path_from_components(
            resolved.iter().map(String::as_str),
        ))
    }

    /// Retrieves metadata for the final target after resolving symbolic links.
    ///
    /// This resolves symbolic links in every component of the requested path.
    /// Use [`AfcClient::get_file_info`] when metadata for a symbolic link itself
    /// is required, such as before deleting or renaming the link.
    pub async fn get_file_info_resolved(
        &mut self,
        path: impl Into<String>,
    ) -> Result<ResolvedFileInfo, IdeviceError> {
        let requested_path = path.into();
        let resolved_path = self.resolve_path(&requested_path).await?;
        let info = self.get_file_info(&resolved_path).await?;

        Ok(ResolvedFileInfo {
            requested_path,
            resolved_path,
            info,
        })
    }

    /// Retrieves information about the device's filesystem
    ///
    /// # Returns
    /// A `DeviceInfo` struct containing device filesystem information
    pub async fn get_device_info(&mut self) -> Result<DeviceInfo, IdeviceError> {
        let header_len = AfcPacketHeader::LEN;

        let header = AfcPacketHeader {
            magic: MAGIC,
            entire_len: header_len, // it's the same since the payload is empty for this
            header_payload_len: header_len,
            packet_num: self.package_number,
            operation: AfcOpcode::GetDevInfo,
        };
        self.package_number += 1;

        let packet = AfcPacket {
            header,
            header_payload: Vec::new(),
            payload: Vec::new(),
        };

        self.send(packet).await?;
        let res = self.read().await?;

        let strings: Vec<String> = res
            .payload
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        let mut kvs: HashMap<String, String> = strings
            .chunks_exact(2)
            .map(|chunk| (chunk[0].clone(), chunk[1].clone()))
            .collect();

        let model = kvs.remove("Model").ok_or(AfcError::MissingAttribute)?;
        let total_bytes = kvs
            .remove("FSTotalBytes")
            .and_then(|x| x.parse::<usize>().ok())
            .ok_or(AfcError::MissingAttribute)?;
        let free_bytes = kvs
            .remove("FSFreeBytes")
            .and_then(|x| x.parse::<usize>().ok())
            .ok_or(AfcError::MissingAttribute)?;
        let block_size = kvs
            .remove("FSBlockSize")
            .and_then(|x| x.parse::<usize>().ok())
            .ok_or(AfcError::MissingAttribute)?;

        if !kvs.is_empty() {
            warn!("Device info kvs not empty: {kvs:?}");
        }

        Ok(DeviceInfo {
            model,
            total_bytes,
            free_bytes,
            block_size,
        })
    }

    /// Removes a file or directory
    ///
    /// # Arguments
    /// * `path` - Path to the file or directory to remove
    pub async fn remove(&mut self, path: impl Into<String>) -> Result<(), IdeviceError> {
        let path = path.into();
        let header_payload = path.as_bytes().to_vec();
        let header_len = header_payload.len() as u64 + AfcPacketHeader::LEN;

        let header = AfcPacketHeader {
            magic: MAGIC,
            entire_len: header_len, // it's the same since the payload is empty for this
            header_payload_len: header_len,
            packet_num: self.package_number,
            operation: AfcOpcode::RemovePath,
        };
        self.package_number += 1;

        let packet = AfcPacket {
            header,
            header_payload,
            payload: Vec::new(),
        };

        self.send(packet).await?;
        self.read().await?; // read a response to check for errors

        Ok(())
    }

    /// Recursively removes a directory and all its contents
    ///
    /// # Arguments
    /// * `path` - Path to the directory to remove
    pub async fn remove_all(&mut self, path: impl Into<String>) -> Result<(), IdeviceError> {
        let path = path.into();
        let header_payload = path.as_bytes().to_vec();
        let header_len = header_payload.len() as u64 + AfcPacketHeader::LEN;

        let header = AfcPacketHeader {
            magic: MAGIC,
            entire_len: header_len, // it's the same since the payload is empty for this
            header_payload_len: header_len,
            packet_num: self.package_number,
            operation: AfcOpcode::RemovePathAndContents,
        };
        self.package_number += 1;

        let packet = AfcPacket {
            header,
            header_payload,
            payload: Vec::new(),
        };

        self.send(packet).await?;
        self.read().await?; // read a response to check for errors

        Ok(())
    }

    /// Opens a file on the device
    ///
    /// # Arguments
    /// * `path` - Path to the file to open
    /// * `mode` - Opening mode (read, write, etc.)
    ///
    /// # Returns
    /// A `FileDescriptor` struct for the opened file
    pub async fn open<'f>(
        &'f mut self,
        path: impl Into<String>,
        mode: AfcFopenMode,
    ) -> Result<FileDescriptor<'f>, IdeviceError> {
        let path = path.into();
        let mut header_payload = (mode as u64).to_le_bytes().to_vec();
        header_payload.extend(path.as_bytes());
        let header_len = header_payload.len() as u64 + AfcPacketHeader::LEN;

        let header = AfcPacketHeader {
            magic: MAGIC,
            entire_len: header_len, // it's the same since the payload is empty for this
            header_payload_len: header_len,
            packet_num: self.package_number,
            operation: AfcOpcode::FileOpen,
        };
        self.package_number += 1;

        let packet = AfcPacket {
            header,
            header_payload,
            payload: Vec::new(),
        };

        self.send(packet).await?;
        let res = self.read().await?;
        if res.header_payload.len() < 8 {
            warn!("Header payload fd is less than 8 bytes");
            return Err(IdeviceError::UnexpectedResponse(
                "AFC FileOpen response header payload too short for fd".into(),
            ));
        }
        let fd = u64::from_le_bytes(res.header_payload[..8].try_into().unwrap());

        // we know it's a valid fd
        Ok(unsafe { FileDescriptor::new(self, fd, path) })
    }

    /// Opens an owned file on the device
    ///
    /// # Arguments
    /// * `path` - Path to the file to open
    /// * `mode` - Opening mode (read, write, etc.)
    ///
    /// # Returns
    /// A `OwnedFileDescriptor` struct for the opened file
    pub async fn open_owned(
        mut self,
        path: impl Into<String>,
        mode: AfcFopenMode,
    ) -> Result<OwnedFileDescriptor, IdeviceError> {
        let path = path.into();
        let mut header_payload = (mode as u64).to_le_bytes().to_vec();
        header_payload.extend(path.as_bytes());
        let header_len = header_payload.len() as u64 + AfcPacketHeader::LEN;

        let header = AfcPacketHeader {
            magic: MAGIC,
            entire_len: header_len, // it's the same since the payload is empty for this
            header_payload_len: header_len,
            packet_num: self.package_number,
            operation: AfcOpcode::FileOpen,
        };
        self.package_number += 1;

        let packet = AfcPacket {
            header,
            header_payload,
            payload: Vec::new(),
        };

        self.send(packet).await?;
        let res = self.read().await?;
        if res.header_payload.len() < 8 {
            warn!("Header payload fd is less than 8 bytes");
            return Err(IdeviceError::UnexpectedResponse(
                "AFC FileOpen response header payload too short for fd".into(),
            ));
        }
        let fd = u64::from_le_bytes(res.header_payload[..8].try_into().unwrap());

        // we know it's a valid fd
        Ok(unsafe { OwnedFileDescriptor::new(self, fd, path) })
    }

    /// Creates a hard or symbolic link
    ///
    /// # Arguments
    /// * `target` - Target path of the link
    /// * `source` - Path where the link should be created
    /// * `kind` - Type of link to create (hard or symbolic)
    pub async fn link(
        &mut self,
        target: impl Into<String>,
        source: impl Into<String>,
        kind: opcode::LinkType,
    ) -> Result<(), IdeviceError> {
        let target = target.into();
        let source = source.into();

        let mut header_payload = (kind as u64).to_le_bytes().to_vec();
        header_payload.extend(target.as_bytes());
        header_payload.push(0);
        header_payload.extend(source.as_bytes());
        header_payload.push(0);

        let header_len = header_payload.len() as u64 + AfcPacketHeader::LEN;

        let header = AfcPacketHeader {
            magic: MAGIC,
            entire_len: header_len,
            header_payload_len: header_len,
            packet_num: self.package_number,
            operation: AfcOpcode::MakeLink,
        };
        self.package_number += 1;

        let packet = AfcPacket {
            header,
            header_payload,
            payload: Vec::new(),
        };

        self.send(packet).await?;
        self.read().await?;

        Ok(())
    }

    /// Renames a file or directory
    ///
    /// # Arguments
    /// * `source` - Current path of the file/directory
    /// * `target` - New path for the file/directory
    pub async fn rename(
        &mut self,
        source: impl Into<String>,
        target: impl Into<String>,
    ) -> Result<(), IdeviceError> {
        let target = target.into();
        let source = source.into();

        let mut header_payload = source.as_bytes().to_vec();
        header_payload.push(0);
        header_payload.extend(target.as_bytes());
        header_payload.push(0);

        let header_len = header_payload.len() as u64 + AfcPacketHeader::LEN;

        let header = AfcPacketHeader {
            magic: MAGIC,
            entire_len: header_len,
            header_payload_len: header_len,
            packet_num: self.package_number,
            operation: AfcOpcode::RenamePath,
        };
        self.package_number += 1;

        let packet = AfcPacket {
            header,
            header_payload,
            payload: Vec::new(),
        };

        self.send(packet).await?;
        self.read().await?;

        Ok(())
    }

    /// Reads a response packet from the device
    ///
    /// # Returns
    /// The received `AfcPacket`
    pub async fn read(&mut self) -> Result<AfcPacket, IdeviceError> {
        let res = AfcPacket::read(&mut self.idevice).await?;
        if res.header.operation == AfcOpcode::Status {
            if res.header_payload.len() < 8 {
                tracing::error!("AFC returned error opcode, but not a code");
                return Err(IdeviceError::UnexpectedResponse(
                    "AFC error status response too short for error code".into(),
                ));
            }
            let code = u64::from_le_bytes(res.header_payload[..8].try_into().unwrap());
            let e = AfcError::from(code);
            if e == AfcError::Success {
                return Ok(res);
            } else {
                return Err(IdeviceError::Afc(e));
            }
        }
        Ok(res)
    }

    /// Sends a packet to the device
    ///
    /// # Arguments
    /// * `packet` - The packet to send
    pub async fn send(&mut self, packet: AfcPacket) -> Result<(), IdeviceError> {
        let packet = packet.serialize();
        self.idevice.send_raw(&packet).await?;
        Ok(())
    }
}

fn normalize_afc_path_components(
    base: &[String],
    path: &str,
) -> Result<VecDeque<String>, IdeviceError> {
    if path.contains('\0') {
        return Err(IdeviceError::UnexpectedResponse(
            "AFC path contains a NUL byte".into(),
        ));
    }

    let mut components = if path.starts_with('/') {
        Vec::new()
    } else {
        base.to_vec()
    };
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component.to_string()),
        }
    }
    Ok(components.into())
}

fn afc_path_from_components<'a>(components: impl Iterator<Item = &'a str>) -> String {
    let mut path = String::from("/");
    path.push_str(&components.collect::<Vec<_>>().join("/"));
    path
}

#[cfg(test)]
mod path_tests {
    use super::{afc_path_from_components, normalize_afc_path_components};

    fn normalize(base: &[&str], path: &str) -> String {
        let base = base
            .iter()
            .map(|part| (*part).to_string())
            .collect::<Vec<_>>();
        let components = normalize_afc_path_components(&base, path).unwrap();
        afc_path_from_components(components.iter().map(String::as_str))
    }

    #[test]
    fn normalizes_absolute_afc_paths() {
        assert_eq!(
            normalize(&["ignored"], "/private//var/./mobile"),
            "/private/var/mobile"
        );
        assert_eq!(normalize(&[], "/../../var"), "/var");
    }

    #[test]
    fn resolves_relative_targets_against_the_link_parent() {
        assert_eq!(normalize(&["private", "var"], "../etc"), "/private/etc");
        assert_eq!(normalize(&["a"], r"directory\name"), r"/a/directory\name");
    }

    #[test]
    fn rejects_nul_bytes() {
        assert!(normalize_afc_path_components(&[], "bad\0path").is_err());
    }
}

#[cfg(feature = "rsd")]
impl crate::RsdService for AfcClient {
    fn rsd_service_name() -> std::borrow::Cow<'static, str> {
        crate::obf!("com.apple.afc.shim.remote")
    }
    async fn from_stream(stream: Box<dyn crate::ReadWrite>) -> Result<Self, crate::IdeviceError> {
        let mut idevice = crate::Idevice::new(stream, "");
        idevice.rsd_checkin().await?;
        Ok(Self::new(idevice))
    }
}
