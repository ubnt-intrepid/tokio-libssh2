//! SFTP subsystem.

use crate::{
    error::{Result, Ssh2Error},
    session::Session,
};
use futures::{
    future::poll_fn,
    task::{self, Poll},
};
use libssh2_sys as sys;
use std::{
    ffi::OsStr, //
    fmt,
    io,
    mem,
    os::unix::prelude::*,
    path::{Path, PathBuf},
    pin::Pin,
    ptr::{self, NonNull},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// The metadata about a remote file.
///
/// This type is ABI-compatible with `LIBSSH2_SFTP_ATTRIBUTES`.
#[repr(transparent)]
pub struct FileAttr(sys::LIBSSH2_SFTP_ATTRIBUTES);

impl fmt::Debug for FileAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileAttr")
            .field("permissions", &self.permissions())
            .field("filesize", &self.filesize())
            .field("uid", &self.uid())
            .field("gid", &self.gid())
            .field("atime", &self.atime())
            .field("mtime", &self.mtime())
            .finish()
    }
}

impl FileAttr {
    #[inline]
    fn get<F, R>(&self, flag: libc::c_ulong, f: F) -> Option<R>
    where
        F: FnOnce(&Self) -> R,
    {
        if self.0.flags & flag != 0 {
            Some(f(self))
        } else {
            None
        }
    }

    /// Return the permission flags of the file, if specified.
    pub fn permissions(&self) -> Option<u64> {
        self.get(sys::LIBSSH2_SFTP_ATTR_PERMISSIONS, |this| {
            this.0.permissions
        })
    }

    /// Return the file size of the file in bytes, if specified.
    pub fn filesize(&self) -> Option<u64> {
        self.get(sys::LIBSSH2_SFTP_ATTR_SIZE, |this| this.0.filesize)
    }

    /// Return the user ID of the file owner, if specified.
    pub fn uid(&self) -> Option<u32> {
        self.get(sys::LIBSSH2_SFTP_ATTR_UIDGID, |this| this.0.uid as u32)
    }

    /// Returns the group ID of the file owner, if specified.
    pub fn gid(&self) -> Option<u32> {
        self.get(sys::LIBSSH2_SFTP_ATTR_UIDGID, |this| this.0.gid as u32)
    }

    /// Return the last access time of the file in seconds, if specified.
    pub fn atime(&self) -> Option<u64> {
        self.get(sys::LIBSSH2_SFTP_ATTR_ACMODTIME, |this| this.0.atime)
    }

    /// Return the last modified time of the file in seconds, if specified.
    pub fn mtime(&self) -> Option<u64> {
        self.get(sys::LIBSSH2_SFTP_ATTR_ACMODTIME, |this| this.0.mtime)
    }
}

#[derive(Debug)]
pub struct DirEntry {
    path: PathBuf,
    attr: FileAttr,
}

#[derive(Debug, Default)]
pub struct OpenOptions {
    flags: libc::c_ulong,
    mode: libc::c_long,
}

impl OpenOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn set_flag(&mut self, flag: libc::c_ulong, enabled: bool) {
        if enabled {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }

    pub fn read(&mut self, enabled: bool) -> &mut Self {
        self.set_flag(sys::LIBSSH2_FXF_READ, enabled);
        self
    }

    pub fn write(&mut self, enabled: bool) -> &mut Self {
        self.set_flag(sys::LIBSSH2_FXF_WRITE, enabled);
        self
    }

    pub fn append(&mut self, enabled: bool) -> &mut Self {
        self.set_flag(sys::LIBSSH2_FXF_APPEND, enabled);
        self
    }

    pub fn create(&mut self, enabled: bool) -> &mut Self {
        self.set_flag(sys::LIBSSH2_FXF_CREAT, enabled);
        self
    }

    pub fn truncate(&mut self, enabled: bool) -> &mut Self {
        self.set_flag(sys::LIBSSH2_FXF_TRUNC, enabled);
        self
    }

    pub fn exclusive(&mut self, enabled: bool) -> &mut Self {
        self.set_flag(sys::LIBSSH2_FXF_EXCL, enabled);
        self
    }

    pub fn mode(&mut self, mode: i32) -> &mut Self {
        self.mode = mode as i64;
        self
    }

    pub async fn open<'a, 'sess, P>(
        &self,
        path: P,
        sftp: &'a mut Sftp<'sess>,
    ) -> Result<File<'a, 'sess>>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let raw = poll_fn(|cx| sftp.poll_open(cx, path, self, sys::LIBSSH2_SFTP_OPENFILE)).await?;
        Ok(File(Handle { raw, sftp }))
    }
}

/// A handle to a remote filesystem over SFTP.
pub struct Sftp<'sess> {
    raw: NonNull<sys::LIBSSH2_SFTP>,
    sess: &'sess mut Session,
}

impl Drop for Sftp<'_> {
    fn drop(&mut self) {
        unsafe {
            // FIXME: should we handle EAGAIN at here?
            let _ = sys::libssh2_sftp_shutdown(self.raw.as_ptr());
        }
    }
}

impl<'sess> Sftp<'sess> {
    pub(crate) fn new(raw: NonNull<sys::LIBSSH2_SFTP>, sess: &'sess mut Session) -> Self {
        Self { raw, sess }
    }

    fn poll_stat(
        &mut self,
        cx: &mut task::Context<'_>,
        path: &Path,
        stat_type: libc::c_int,
        attrs: *mut sys::LIBSSH2_SFTP_ATTRIBUTES,
    ) -> Poll<Result<()>> {
        unsafe {
            let sftp = self.raw.as_mut();
            let path = path.as_os_str().as_bytes();
            self.sess.poll_with(cx, |_| {
                let rc = sys::libssh2_sftp_stat_ex(
                    sftp,
                    path.as_ptr() as *const libc::c_char,
                    path.as_ref().len() as libc::c_uint,
                    stat_type,
                    attrs,
                );

                match rc {
                    0 => Ok(()),
                    _ => Err(Ssh2Error::from_code(
                        sys::libssh2_sftp_last_error(sftp) as libc::c_int
                    )),
                }
            })
        }
    }

    /// Acquire the metadata for a file.
    pub async fn stat(&mut self, path: impl AsRef<Path>) -> Result<FileAttr> {
        let path = path.as_ref();
        unsafe {
            let mut stbuf = mem::MaybeUninit::zeroed();
            poll_fn(|cx| {
                self.poll_stat(
                    cx, //
                    path,
                    sys::LIBSSH2_SFTP_STAT,
                    stbuf.as_mut_ptr(),
                )
            })
            .await?;
            Ok(FileAttr(stbuf.assume_init()))
        }
    }

    /// Acquire the metadata for a file.
    pub async fn lstat(&mut self, path: impl AsRef<Path>) -> Result<FileAttr> {
        let path = path.as_ref();
        unsafe {
            let mut stbuf = mem::MaybeUninit::zeroed();
            poll_fn(|cx| {
                self.poll_stat(
                    cx, //
                    path,
                    sys::LIBSSH2_SFTP_LSTAT,
                    stbuf.as_mut_ptr(),
                )
            })
            .await?;
            Ok(FileAttr(stbuf.assume_init()))
        }
    }

    pub async fn setstat(&mut self, path: impl AsRef<Path>, attrs: FileAttr) -> Result<()> {
        let path = path.as_ref();
        let mut attrs = attrs;
        poll_fn(|cx| {
            self.poll_stat(
                cx, //
                path,
                sys::LIBSSH2_SFTP_SETSTAT,
                &mut attrs.0,
            )
        })
        .await?;
        Ok(())
    }

    fn poll_open(
        &mut self,
        cx: &mut task::Context<'_>,
        path: &Path,
        options: &OpenOptions,
        open_type: libc::c_int,
    ) -> Poll<Result<NonNull<sys::LIBSSH2_SFTP_HANDLE>>> {
        let sftp = &mut self.raw;
        let path = path.as_os_str().as_bytes();
        let flags = options.flags;
        let mode = options.mode;
        self.sess.poll_with(cx, |sess| {
            let raw = NonNull::new(unsafe {
                sys::libssh2_sftp_open_ex(
                    sftp.as_mut(),
                    path.as_ptr() as *const libc::c_char,
                    path.as_ref().len() as libc::c_uint,
                    flags,
                    mode,
                    open_type,
                )
            });
            raw.ok_or_else(|| sess.last_error())
        })
    }

    pub async fn open<'a>(&'a mut self, path: impl AsRef<Path>) -> Result<File<'a, 'sess>> {
        OpenOptions::new()
            .read(true)
            .open(path.as_ref(), self)
            .await
    }

    pub async fn opendir<'a>(&'a mut self, path: impl AsRef<Path>) -> Result<Dir<'a, 'sess>> {
        let path = path.as_ref();
        let mut options = OpenOptions::new();
        options.read(true);
        let raw =
            poll_fn(|cx| self.poll_open(cx, path, &options, sys::LIBSSH2_SFTP_OPENDIR)).await?;
        Ok(Dir(Handle { raw, sftp: self }))
    }
}

struct Handle<'a, 'sess> {
    raw: NonNull<sys::LIBSSH2_SFTP_HANDLE>,
    sftp: &'a mut Sftp<'sess>,
}

impl Drop for Handle<'_, '_> {
    fn drop(&mut self) {
        unsafe {
            // FIXME: should we handle EAGAIN at here?
            let _rc = sys::libssh2_sftp_close_handle(self.raw.as_ptr());
        }
    }
}

impl Handle<'_, '_> {
    fn poll_fstat(
        &mut self,
        cx: &mut task::Context<'_>,
        attrs: *mut sys::LIBSSH2_SFTP_ATTRIBUTES,
        setstat: bool,
    ) -> Poll<Result<()>> {
        let handle = &mut self.raw;
        let sftp = &mut self.sftp.raw;
        let setstat = if setstat { 1 } else { 0 };
        self.sftp.sess.poll_with(cx, |_| {
            let rc = unsafe { sys::libssh2_sftp_fstat_ex(handle.as_mut(), attrs, setstat) };
            match rc {
                0 => Ok(()),
                _ => Err(Ssh2Error::from_code(unsafe {
                    sys::libssh2_sftp_last_error(sftp.as_mut()) as libc::c_int
                })),
            }
        })
    }

    fn poll_read(&mut self, cx: &mut task::Context<'_>, dst: &mut [u8]) -> Poll<Result<usize>> {
        let handle = &mut self.raw;
        self.sftp.sess.poll_with(cx, |sess| {
            sess.rc(unsafe {
                sys::libssh2_sftp_read(
                    handle.as_mut(),
                    dst.as_mut_ptr() as *mut libc::c_char,
                    dst.len() as libc::size_t,
                )
            })
            .map(|n| n as usize)
        })
    }

    fn poll_write(&mut self, cx: &mut task::Context<'_>, src: &[u8]) -> Poll<Result<usize>> {
        let handle = &mut self.raw;
        self.sftp.sess.poll_with(cx, |sess| {
            sess.rc(unsafe {
                sys::libssh2_sftp_write(
                    handle.as_mut(),
                    src.as_ptr() as *const libc::c_char,
                    src.len() as libc::size_t,
                )
            })
            .map(|n| n as usize)
        })
    }

    fn poll_fsync(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<()>> {
        let handle = &mut self.raw;
        self.sftp.sess.poll_with(cx, |sess| {
            sess.rc(unsafe { sys::libssh2_sftp_fsync(handle.as_mut()) })
                .map(drop)
        })
    }

    fn poll_readdir(
        &mut self,
        cx: &mut task::Context<'_>,
        pathbuf: &mut Vec<u8>,
        attr: *mut sys::LIBSSH2_SFTP_ATTRIBUTES,
    ) -> Poll<Result<()>> {
        unsafe {
            pathbuf.set_len(pathbuf.capacity());
        }

        let handle = &mut self.raw;
        self.sftp.sess.poll_with(cx, |sess| {
            let res = sess.rc(unsafe {
                sys::libssh2_sftp_readdir_ex(
                    handle.as_mut(),
                    pathbuf.as_mut_ptr() as *mut libc::c_char,
                    pathbuf.len() as libc::size_t,
                    ptr::null_mut(),
                    0,
                    attr,
                )
            });
            unsafe {
                pathbuf.set_len(match res {
                    Ok(n) => n as usize,
                    Err(..) => 0,
                });
            }
            res.map(drop)
        })
    }
}

/// A file handle corresponding to an SFTP connection.
pub struct File<'a, 'sess>(Handle<'a, 'sess>);

// TODO: AsyncSeek

impl File<'_, '_> {
    pub async fn stat(&mut self) -> Result<FileAttr> {
        unsafe {
            let mut stbuf = mem::MaybeUninit::zeroed();
            poll_fn(|cx| self.0.poll_fstat(cx, stbuf.as_mut_ptr(), false)).await?;
            Ok(FileAttr(stbuf.assume_init()))
        }
    }

    pub async fn setstat(&mut self, attrs: FileAttr) -> Result<()> {
        let mut attrs = attrs;
        poll_fn(|cx| self.0.poll_fstat(cx, &mut attrs.0, true)).await?;
        Ok(())
    }

    pub async fn read<'a>(&'a mut self, dst: &'a mut [u8]) -> Result<usize> {
        poll_fn(|cx| self.0.poll_read(cx, dst)).await
    }

    pub async fn write<'a>(&'a mut self, src: &'a [u8]) -> Result<usize> {
        poll_fn(|cx| self.0.poll_write(cx, src)).await
    }

    /// Synchronize the file data and metada to the disk on the remote server.
    pub async fn fsync(&mut self) -> Result<()> {
        poll_fn(|cx| self.0.poll_fsync(cx)).await
    }
}

impl AsyncRead for File<'_, '_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        dst: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .0
            .poll_read(cx, dst)
            .map_err(|err| err.into_io_error())
    }
}

impl AsyncWrite for File<'_, '_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .0
            .poll_write(cx, src)
            .map_err(|err| err.into_io_error())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .0
            .poll_fsync(cx)
            .map_err(|err| err.into_io_error())
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A directory handle corresponding to an SFTP connection.
pub struct Dir<'a, 'sess>(Handle<'a, 'sess>);

impl Dir<'_, '_> {
    /// Acquire the attribute information of this directory.
    pub async fn stat(&mut self) -> Result<FileAttr> {
        unsafe {
            let mut stbuf = mem::MaybeUninit::zeroed();
            poll_fn(|cx| self.0.poll_fstat(cx, stbuf.as_mut_ptr(), false)).await?;
            Ok(FileAttr(stbuf.assume_init()))
        }
    }

    /// Set the attribute information of the directory.
    pub async fn setstat(&mut self, attrs: FileAttr) -> Result<()> {
        let mut attrs = attrs;
        poll_fn(|cx| self.0.poll_fstat(cx, &mut attrs.0, true)).await?;
        Ok(())
    }

    /// Read an entry from the directory, if any.
    #[inline]
    pub async fn readdir(&mut self) -> Option<Result<DirEntry>> {
        self.readdir_inner().await.transpose()
    }

    async fn readdir_inner(&mut self) -> Result<Option<DirEntry>> {
        let mut path = Vec::with_capacity(1024);
        let mut attr = mem::MaybeUninit::zeroed();
        poll_fn(|cx| {
            self.0.poll_readdir(
                cx, //
                &mut path,
                attr.as_mut_ptr(),
            )
        })
        .await?;

        if path.is_empty() {
            return Ok(None);
        };

        Ok(Some(DirEntry {
            path: PathBuf::from(OsStr::from_bytes(&*path)),
            attr: FileAttr(unsafe { attr.assume_init() }),
        }))
    }
}
