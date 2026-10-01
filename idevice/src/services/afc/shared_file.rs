// Jackson Coxson
// Uncore <https://github.com/uncor3>
//
//! An AFC file whose connection is shared with its caller.
//!
//! AFC descriptors require an explicit asynchronous `FileClose` request, which
//! cannot be performed by `Drop` due to many reasons. `SharedFile` separates reading from closing,
//! allowing the reader to be moved (in our case it's ffmpeg_next) while the caller retains a close
//! handle and ownership of the AFC connection is never lost.

use std::{
    future::Future,
    io::SeekFrom,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncSeek, ReadBuf},
    sync::Mutex,
};

use crate::{
    IdeviceError,
    afc::{AfcClient, opcode::AfcFopenMode, opcode::AfcOpcode},
};

const MAX_TRANSFER: usize = 1024 * 1024;

enum PendingResult {
    Bytes(Vec<u8>),
    SeekPos(u64),
}

type PendingFuture =
    Pin<Box<dyn Future<Output = Result<PendingResult, IdeviceError>> + Send + 'static>>;

/// An open file that shares ownership of its AFC connection.
///
/// Split the file before passing its reader to code that takes ownership. The
/// close handle remains with the caller so the device-side file descriptor can
/// still be closed if that code fails or panics.
#[must_use = "the AFC file must be split and closed explicitly"]
pub struct SharedFileDescriptor {
    client: Option<Arc<Mutex<AfcClient>>>,
    fd: u64,
    path: Option<String>,
}

/// The read/seek half of a shared AFC file.
pub struct SharedFileReader {
    client: Arc<Mutex<AfcClient>>,
    fd: u64,
    pending: Option<PendingFuture>,
}

/// The close half of a shared AFC file.
#[must_use = "the AFC file must be closed explicitly"]
pub struct SharedFileCloser {
    client: Arc<Mutex<AfcClient>>,
    fd: u64,
    path: String,
    close_attempted: bool,
}

impl SharedFileDescriptor {
    /// Opens a file using a shared AFC connection.
    pub async fn open(
        client: Arc<Mutex<AfcClient>>,
        path: impl Into<String>,
        mode: AfcFopenMode,
    ) -> Result<Self, IdeviceError> {
        let path = path.into();
        let fd = {
            let mut client_guard = client.lock().await;
            client_guard.open_handle(&path, mode).await?
        };

        Ok(Self {
            client: Some(client),
            fd,
            path: Some(path),
        })
    }

    /// Returns the remote AFC file handle.
    pub fn as_raw_fd(&self) -> u64 {
        self.fd
    }

    /// Separates file I/O from responsibility for closing the remote handle.
    pub fn split(mut self) -> (SharedFileReader, SharedFileCloser) {
        let client = self.client.take().expect("shared AFC file already split");
        let path = self.path.take().expect("shared AFC file already split");

        (
            SharedFileReader {
                client: Arc::clone(&client),
                fd: self.fd,
                pending: None,
            },
            SharedFileCloser {
                client,
                fd: self.fd,
                path,
                close_attempted: false,
            },
        )
    }
}

impl SharedFileReader {
    /// Returns the remote AFC file handle.
    pub fn as_raw_fd(&self) -> u64 {
        self.fd
    }

    fn start_read(&mut self, amount: usize) {
        let client = Arc::clone(&self.client);
        let fd = self.fd;

        self.pending = Some(Box::pin(async move {
            let mut collected = Vec::with_capacity(amount);
            let mut client = client.lock().await;

            for offset in (0..amount).step_by(MAX_TRANSFER) {
                let chunk = (amount - offset).min(MAX_TRANSFER);
                let header_payload = [fd.to_le_bytes(), (chunk as u64).to_le_bytes()].concat();
                let response = client
                    .file_request(AfcOpcode::Read, header_payload, Vec::new())
                    .await?;

                if response.payload.is_empty() {
                    break;
                }

                let response_len = response.payload.len();
                collected.extend(response.payload);
                if response_len < chunk {
                    break;
                }
            }

            Ok(PendingResult::Bytes(collected))
        }));
    }

    fn schedule_seek(&mut self, position: SeekFrom) {
        let client = Arc::clone(&self.client);
        let fd = self.fd;

        self.pending = Some(Box::pin(async move {
            let (offset, whence) = match position {
                SeekFrom::Start(offset) => (offset as i64, 0_u64),
                SeekFrom::Current(offset) => (offset, 1_u64),
                SeekFrom::End(offset) => (offset, 2_u64),
            };

            let mut client = client.lock().await;
            let header_payload =
                [fd.to_le_bytes(), whence.to_le_bytes(), offset.to_le_bytes()].concat();

            client
                .file_request(AfcOpcode::FileSeek, header_payload, Vec::new())
                .await?;

            let response = client
                .file_request(AfcOpcode::FileTell, fd.to_le_bytes().to_vec(), Vec::new())
                .await?;

            let position_bytes = response.header_payload.get(..8).ok_or_else(|| {
                IdeviceError::UnexpectedResponse(
                    "AFC FileTell response missing position bytes".into(),
                )
            })?;
            let position = u64::from_le_bytes(position_bytes.try_into().unwrap());

            Ok(PendingResult::SeekPos(position))
        }));
    }
}

impl SharedFileCloser {
    /// Returns the remote AFC file handle.
    pub fn as_raw_fd(&self) -> u64 {
        self.fd
    }

    /// Closes the device-side file descriptor.
    pub async fn close(mut self) -> Result<(), IdeviceError> {
        self.close_attempted = true;

        let mut client = self.client.lock().await;
        client
            .file_request(
                AfcOpcode::FileClose,
                self.fd.to_le_bytes().to_vec(),
                Vec::new(),
            )
            .await?;

        Ok(())
    }
}

impl AsyncRead for SharedFileReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.pending.is_none() {
            self.start_read(buf.remaining());
        }

        let result = match self.pending.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.pending = None;

        match result {
            Ok(PendingResult::Bytes(contents)) => {
                buf.put_slice(&contents);
                Poll::Ready(Ok(()))
            }
            Ok(PendingResult::SeekPos(_)) => unreachable!("seek future stored for a read"),
            Err(error) => Poll::Ready(Err(std::io::Error::other(error.to_string()))),
        }
    }
}

impl AsyncSeek for SharedFileReader {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        if self.pending.is_some() {
            return Err(std::io::Error::other(
                "another AFC file operation is still pending",
            ));
        }
        self.get_mut().schedule_seek(position);
        Ok(())
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(Ok(0));
        };

        let result = match pending.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.pending = None;

        match result {
            Ok(PendingResult::SeekPos(position)) => Poll::Ready(Ok(position)),
            Ok(PendingResult::Bytes(_)) => unreachable!("read future stored for a seek"),
            Err(error) => Poll::Ready(Err(std::io::Error::other(error.to_string()))),
        }
    }
}

impl std::fmt::Debug for SharedFileDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedFileDescriptor")
            .field("fd", &self.fd)
            .field("path", &self.path)
            .finish()
    }
}

impl std::fmt::Debug for SharedFileReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedFileReader")
            .field("fd", &self.fd)
            .finish()
    }
}

impl std::fmt::Debug for SharedFileCloser {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedFileCloser")
            .field("fd", &self.fd)
            .field("path", &self.path)
            .field("close_attempted", &self.close_attempted)
            .finish()
    }
}

impl Drop for SharedFileDescriptor {
    fn drop(&mut self) {
        if self.client.is_some() {
            debug_assert!(
                false,
                "AFC file descriptor for {:?} dropped without being split and closed",
                self.path
            );
            println!(
                "error: AFC file descriptor dropped without being split and closed ({:?})",
                self.path
            );
        }
    }
}

impl Drop for SharedFileCloser {
    fn drop(&mut self) {
        if !self.close_attempted {
            debug_assert!(
                false,
                "AFC file descriptor for {:?} dropped without calling .close().await",
                self.path
            );
            println!(
                "error: AFC file descriptor dropped without calling .close().await ({})",
                self.path
            );
        }
    }
}
