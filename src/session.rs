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
    io,
    os::unix::prelude::*,
    pin::Pin,
    ptr::{self, NonNull},
};
use tokio::io::PollEvented;

pub struct Session {
    raw: NonNull<sys::LIBSSH2_SESSION>,
    stream: Option<PollEvented<TcpStream>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        tracing::trace!("Session::drop");
        unsafe {
            let _ = sys::libssh2_session_free(self.raw.as_ptr());
        }
    }
}

impl Session {
    pub fn new() -> Result<Self> {
        tracing::trace!("Session::new");

        sys::init();

        unsafe {
            let mut raw = NonNull::new(sys::libssh2_session_init_ex(
                /* alloc */ None,
                /* free */ None,
                /* realloc */ None,
                ptr::null_mut(),
            ))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to init the session"))?;

            sys::libssh2_session_set_blocking(raw.as_mut(), 0);

            Ok(Self { raw, stream: None })
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

    pub(crate) fn poll_read_with<F, R>(
        &mut self,
        cx: &mut task::Context<'_>,
        f: F,
    ) -> Poll<Result<R>>
    where
        F: FnOnce(&mut Self) -> std::result::Result<R, Ssh2Error>,
    {
        use mio::unix::UnixReady;
        use mio::Ready;

        let mut mask = Ready::readable();
        mask |= UnixReady::error();

        ready!(self.stream_mut().poll_read_ready(cx, mask))?;

        match f(&mut *self) {
            Ok(ret) => Poll::Ready(Ok(ret)),
            Err(ref err) if err.code() == sys::LIBSSH2_ERROR_EAGAIN => {
                self.stream_mut().clear_read_ready(cx, mask)?;
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err.into())),
        }
    }

    pub(crate) fn poll_write_with<F, R>(
        &mut self,
        cx: &mut task::Context<'_>,
        f: F,
    ) -> Poll<Result<R>>
    where
        F: FnOnce(&mut Self) -> std::result::Result<R, Ssh2Error>,
    {
        ready!(self.stream_mut().poll_write_ready(cx))?;

        match f(&mut *self) {
            Ok(ret) => Poll::Ready(Ok(ret)),
            Err(ref err) if err.code() == sys::LIBSSH2_ERROR_EAGAIN => {
                self.stream_mut().clear_write_ready(cx)?;
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err.into())),
        }
    }

    fn poll_handshake(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut PollEvented<TcpStream>,
    ) -> Poll<Result<()>> {
        use mio::unix::UnixReady;
        use mio::Ready;

        let mut mask = Ready::readable();
        mask |= UnixReady::error();

        ready!(stream.poll_read_ready(cx, mask))?;

        let rc = unsafe {
            sys::libssh2_session_handshake(
                self.raw.as_mut(), //
                stream.get_ref().as_raw_fd(),
            )
        };

        match rc {
            0 => Poll::Ready(Ok(())),
            sys::LIBSSH2_ERROR_EAGAIN => {
                stream.clear_read_ready(cx, mask)?;
                Poll::Pending
            }
            code => Poll::Ready(Err(Ssh2Error::from_code(code).into())),
        }
    }

    /// Start the transport layer protocol negotiation with the connected host.
    pub async fn handshake(&mut self, stream: std::net::TcpStream) -> Result<()> {
        tracing::trace!("Session::handshake");
        let mut stream = PollEvented::new(TcpStream::from_stream(stream)?)?;
        poll_fn(|cx| self.poll_handshake(cx, &mut stream)).await?;
        tracing::trace!("handshake completed");
        self.stream = Some(stream);
        Ok(())
    }

    pub async fn authenticate<'a, A>(&'a mut self, username: &'a str, auth: A) -> Result<()>
    where
        A: Authenticator + Unpin,
    {
        tracing::trace!("Session::authenticate");
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

    pub async fn open_channel<'a>(
        &'a mut self,
        channel_type: &'a str,
        window_size: Option<u32>,
        packet_size: Option<u32>,
        msg: Option<&'a str>,
    ) -> Result<Channel<'a>> {
        tracing::trace!("Session::open_channel(type={:?})", channel_type);

        let raw = poll_fn(|cx| {
            self.poll_write_with(cx, |sess| {
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
        tracing::trace!("Session::sftp");
        let raw = poll_fn(|cx| {
            self.poll_write_with(cx, |sess| {
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
