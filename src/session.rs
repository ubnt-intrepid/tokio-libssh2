use crate::{
    auth::{AuthContext, Authenticator},
    channel::Channel,
    error::{Result, Ssh2Error},
    sftp::Sftp,
};
use futures::{
    future::poll_fn,
    ready,
    task::{self, Poll},
};
use libssh2_sys as sys;
use mio::net::TcpStream;
use std::{
    ffi::{CStr, CString},
    pin::Pin,
    ptr::{self, NonNull},
};
use tokio::io::PollEvented;

bitflags::bitflags! {
    #[repr(transparent)]
    struct BlockDirections: libc::c_int {
        const READ = sys::LIBSSH2_SESSION_BLOCK_INBOUND;
        const WRITE = sys::LIBSSH2_SESSION_BLOCK_OUTBOUND;
    }
}

/// A handle to an SSH session.
pub struct Session {
    raw: NonNull<sys::LIBSSH2_SESSION>,
    stream: Option<PollEvented<TcpStream>>,
    blocking_directions: Option<BlockDirections>,
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            let _ = sys::libssh2_session_free(self.raw.as_ptr());
        }
    }
}

impl Session {
    /// Initialize an SSH session.
    pub fn new() -> Result<Self> {
        sys::init();

        unsafe {
            let raw = NonNull::new(sys::libssh2_session_init_ex(
                /* alloc */ None,
                /* free */ None,
                /* realloc */ None,
                ptr::null_mut(),
            ))
            .ok_or_else(|| Ssh2Error::new(0, "failed to initialize SSH session"))?;

            Ok(Self {
                raw,
                stream: None,
                blocking_directions: None,
            })
        }
    }

    pub(crate) unsafe fn as_raw_ptr(&mut self) -> *mut sys::LIBSSH2_SESSION {
        self.raw.as_mut()
    }

    pub(crate) fn last_error(&mut self) -> Ssh2Error {
        unsafe { Ssh2Error::last_error(self.raw.as_mut()) } //
            .unwrap_or_else(Ssh2Error::unknown)
    }

    pub(crate) fn rc<R: ReturnCode>(&mut self, rc: R) -> std::result::Result<R, Ssh2Error> {
        if rc.is_success() {
            Ok(rc)
        } else {
            Err(self.last_error())
        }
    }

    fn stream_mut(&mut self) -> &mut PollEvented<TcpStream> {
        self.stream.as_mut().unwrap()
    }

    #[allow(clippy::cognitive_complexity)]
    pub(crate) fn poll_with<F, R>(&mut self, cx: &mut task::Context<'_>, f: F) -> Poll<Result<R>>
    where
        F: FnOnce(&mut Self) -> std::result::Result<R, Ssh2Error>,
    {
        fn read_mask() -> mio::Ready {
            let mut mask = mio::Ready::readable();
            mask |= mio::unix::UnixReady::error();
            mask
        }

        let mut read_ready = false;
        let mut write_ready = false;
        if let Some(directions) = self.blocking_directions {
            if directions.contains(BlockDirections::READ) {
                tracing::trace!("poll read readiness");
                ready!(self.stream_mut().poll_read_ready(cx, read_mask()))?;
                read_ready = true;
            }
            if directions.contains(BlockDirections::WRITE) {
                tracing::trace!("poll write readiness");
                ready!(self.stream_mut().poll_write_ready(cx))?;
                write_ready = true;
            }
        }
        self.blocking_directions.take();

        match f(&mut *self) {
            Ok(ret) => Poll::Ready(Ok(ret)),
            Err(ref err) if err.code() == sys::LIBSSH2_ERROR_EAGAIN => {
                let directions =
                    unsafe { sys::libssh2_session_block_directions(self.raw.as_mut()) };
                self.blocking_directions = Some(BlockDirections::from_bits_truncate(directions));
                tracing::trace!("blocking_directions={:?}", self.blocking_directions);

                let stream = self.stream_mut();
                if read_ready {
                    tracing::trace!("clear read readiness");
                    stream.clear_read_ready(cx, read_mask())?;
                }
                if write_ready {
                    tracing::trace!("clear write readiness");
                    stream.clear_write_ready(cx)?;
                }

                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err.into())),
        }
    }

    /// Set the banner that will be sent to the remote host when the SSH session is started.
    ///
    /// By default, a banner corresponding to the protocol and libssh2 version will be sent.
    pub fn set_banner(&mut self, banner: impl AsRef<str>) -> Result<()> {
        let banner = CString::new(banner.as_ref())?;
        let raw = self.raw.as_ptr();
        self.rc(unsafe { sys::libssh2_session_banner_set(raw, banner.as_ptr()) })?;
        Ok(())
    }

    /// Start the transport layer protocol negotiation with the connected host.
    pub async fn handshake(&mut self, stream: std::net::TcpStream) -> Result<()> {
        #[cfg(unix)]
        fn get_socket_fd(stream: &std::net::TcpStream) -> std::os::unix::io::RawFd {
            use std::os::unix::prelude::*;
            stream.as_raw_fd()
        }

        #[cfg(windows)]
        fn get_socket_fd(stream: &std::net::TcpStream) -> std::os::windows::io::RawSocket {
            use sts::os::windows::prelude::*;
            stream.as_raw_socket()
        }

        let fd = get_socket_fd(&stream);

        let stream = PollEvented::new(TcpStream::from_stream(stream)?)?;
        self.stream.replace(stream);

        poll_fn(|cx| {
            let raw = self.raw.as_ptr();
            self.poll_with(cx, |sess| {
                sess.rc(unsafe { sys::libssh2_session_handshake(raw, fd) })
                    .map(drop)
            })
        })
        .await
    }

    /// Attempt the specified authentication.
    pub async fn authenticate<'a, A>(&'a mut self, username: &'a str, auth: A) -> Result<()>
    where
        A: Authenticator + Unpin,
    {
        let mut auth = auth;
        poll_fn(|cx| {
            Pin::new(&mut auth).poll_authenticate(
                cx,
                &mut AuthContext {
                    sess: self,
                    username: &*username,
                },
            )
        })
        .await
    }

    /// Return whether the session has been successfully authenticated or not.
    pub fn authenticated(&self) -> bool {
        unsafe { sys::libssh2_userauth_authenticated(self.raw.as_ptr()) != 0 }
    }

    /// List the supported authentication methods for an user.
    pub async fn list_userauth(&mut self, username: &str) -> Result<Vec<u8>> {
        let list = poll_fn(|cx| {
            self.poll_with(cx, |sess| {
                let list = NonNull::new(unsafe {
                    sys::libssh2_userauth_list(
                        sess.raw.as_mut(),
                        username.as_ptr() as *const libc::c_char,
                        username.len() as libc::c_uint,
                    )
                })
                .ok_or_else(|| sess.last_error())?;
                Ok(unsafe { CStr::from_ptr(list.as_ptr()).to_owned() })
            })
        })
        .await?;
        Ok(list.into_bytes())
    }

    pub async fn open_channel<'a>(
        &'a mut self,
        channel_type: &'a str,
        window_size: Option<u32>,
        packet_size: Option<u32>,
        msg: Option<&'a str>,
    ) -> Result<Channel<'a>> {
        let raw = poll_fn(|cx| {
            self.poll_with(cx, |sess| {
                let window_size = window_size.unwrap_or(sys::LIBSSH2_CHANNEL_WINDOW_DEFAULT);
                let packet_size = packet_size.unwrap_or(sys::LIBSSH2_CHANNEL_PACKET_DEFAULT);
                let (msg, msg_len) = match msg {
                    Some(msg) => (
                        msg.as_ptr() as *const libc::c_char,
                        msg.len() as libc::c_uint,
                    ),
                    None => (ptr::null(), 0),
                };

                let raw = NonNull::new(unsafe {
                    sys::libssh2_channel_open_ex(
                        sess.raw.as_mut(),
                        channel_type.as_ptr() as *const libc::c_char,
                        channel_type.len() as libc::c_uint,
                        window_size,
                        packet_size,
                        msg,
                        msg_len,
                    )
                });
                raw.ok_or_else(|| sess.last_error())
            })
        })
        .await?;

        Ok(Channel::new(raw, self))
    }

    #[allow(clippy::needless_lifetimes)]
    pub async fn open_channel_session<'sess>(&'sess mut self) -> Result<Channel<'sess>> {
        self.open_channel("session", None, None, None).await
    }

    #[allow(clippy::needless_lifetimes)]
    pub async fn sftp<'sess>(&'sess mut self) -> Result<Sftp<'sess>> {
        let raw = poll_fn(|cx| {
            self.poll_with(cx, |sess| {
                NonNull::new(unsafe { sys::libssh2_sftp_init(sess.raw.as_mut()) }) //
                    .ok_or_else(|| sess.last_error())
            })
        })
        .await?;
        Ok(Sftp::new(raw, self))
    }
}

pub(crate) trait ReturnCode {
    fn is_success(&self) -> bool;
}

impl ReturnCode for libc::c_int {
    fn is_success(&self) -> bool {
        *self >= 0
    }
}

impl ReturnCode for libc::ssize_t {
    fn is_success(&self) -> bool {
        *self >= 0
    }
}
