use crate::{error::Result, session::Session};
use futures::{
    future::poll_fn,
    task::{self, Poll},
};
use libssh2_sys as sys;
use std::{
    io,
    pin::Pin,
    ptr::{self, NonNull},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// A portion of an SSH connection on which data can be read and written.
pub struct Channel<'sess> {
    raw: NonNull<sys::LIBSSH2_CHANNEL>,
    sess: &'sess mut Session,
}

impl Drop for Channel<'_> {
    fn drop(&mut self) {
        tracing::trace!("Channel::drop");
        unsafe {
            // FIXME: should we handle EAGAIN at here?
            sys::libssh2_channel_free(self.raw.as_ptr());
        }
    }
}

impl<'sess> Channel<'sess> {
    pub(crate) fn new(raw: NonNull<sys::LIBSSH2_CHANNEL>, sess: &'sess mut Session) -> Self {
        Self { raw, sess }
    }

    fn poll_setenv(
        &mut self,
        cx: &mut task::Context<'_>,
        name: &str,
        value: &str,
    ) -> Poll<Result<()>> {
        let channel = &mut self.raw;
        self.sess.poll_write_with(cx, |sess| {
            sess.rc(unsafe {
                sys::libssh2_channel_setenv_ex(
                    channel.as_mut(),
                    name.as_ptr() as *const libc::c_char,
                    name.len() as libc::c_uint,
                    value.as_ptr() as *const libc::c_char,
                    value.len() as libc::c_uint,
                )
            })
            .map(drop)
        })
    }

    /// Set an environment variable in the remote channel's process space.
    pub async fn setenv<'a>(&'a mut self, name: &'a str, value: &'a str) -> Result<()> {
        poll_fn(|cx| self.poll_setenv(cx, name, value)).await
    }

    fn poll_process_startup(
        &mut self,
        cx: &mut task::Context<'_>,
        request: &str,
        message: Option<&str>,
    ) -> Poll<Result<()>> {
        let channel = &mut self.raw;
        let (msg, msg_len) = match message {
            Some(msg) => (msg.as_ptr(), msg.len()),
            None => (ptr::null(), 0),
        };
        self.sess.poll_write_with(cx, |sess| {
            sess.rc(unsafe {
                sys::libssh2_channel_process_startup(
                    channel.as_mut(),
                    request.as_ptr() as *const libc::c_char,
                    request.len() as libc::c_uint,
                    msg as *const libc::c_char,
                    msg_len as libc::c_uint,
                )
            })
            .map(drop)
        })
    }

    /// Initiate a request on a session type channel.
    pub async fn process_startup<'a>(
        &'a mut self,
        request: &'a str,
        message: Option<&'a str>,
    ) -> Result<()> {
        tracing::trace!(
            "Channel::startup_process(request={:?}, message={:?})",
            request,
            message
        );
        poll_fn(|cx| self.poll_process_startup(cx, request, message)).await
    }

    /// Start a shell.
    pub async fn shell(&mut self) -> Result<()> {
        self.process_startup("shell", None).await
    }

    /// Execute a command.
    pub async fn exec<'a>(&'a mut self, command: &'a str) -> Result<()> {
        self.process_startup("exec", Some(command)).await
    }

    /// Request a subsystem be started.
    pub async fn subsystem<'a>(&'a mut self, subsystem: &'a str) -> Result<()> {
        self.process_startup("subsystem", Some(subsystem)).await
    }

    /// Return a handle to a particular stream for this channel.
    pub fn stream<'a>(&'a mut self, stream_id: i32) -> Stream<'a, 'sess> {
        Stream {
            channel: self,
            stream_id,
        }
    }

    pub fn exit_status(&self) -> Result<i32> {
        unsafe { Ok(sys::libssh2_channel_get_exit_status(self.raw.as_ptr())) }
    }

    fn poll_read(
        &mut self,
        cx: &mut task::Context<'_>,
        stream_id: i32,
        dst: &mut [u8],
    ) -> Poll<Result<usize>> {
        let channel = &mut self.raw;
        self.sess.poll_read_with(cx, |sess| {
            sess.rc(unsafe {
                sys::libssh2_channel_read_ex(
                    channel.as_mut(),
                    stream_id as libc::c_int,
                    dst.as_mut_ptr() as *mut libc::c_char,
                    dst.len() as libc::size_t,
                )
            })
            .map(|n| n as usize)
        })
    }

    fn poll_write(
        &mut self,
        cx: &mut task::Context<'_>,
        stream_id: i32,
        src: &[u8],
    ) -> Poll<Result<usize>> {
        let channel = &mut self.raw;
        self.sess.poll_write_with(cx, |sess| {
            sess.rc(unsafe {
                sys::libssh2_channel_write_ex(
                    channel.as_mut(),
                    stream_id,
                    src.as_ptr() as *const libc::c_char,
                    src.len(),
                )
            })
            .map(|n| n as usize)
        })
    }

    fn poll_flush(&mut self, cx: &mut task::Context<'_>, stream_id: i32) -> Poll<Result<()>> {
        let channel = &mut self.raw;
        self.sess.poll_write_with(cx, |sess| {
            sess.rc(unsafe { sys::libssh2_channel_flush_ex(channel.as_mut(), stream_id) })
                .map(drop)
        })
    }

    fn poll_close(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<()>> {
        let channel = &mut self.raw;
        self.sess.poll_write_with(cx, |sess| {
            sess.rc(unsafe { sys::libssh2_channel_close(channel.as_mut()) })
                .map(drop)
        })
    }

    pub async fn close(&mut self) -> Result<()> {
        poll_fn(|cx| self.poll_close(cx)).await
    }
}

impl AsyncRead for Channel<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        dst: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream(0)).poll_read(cx, dst)
    }
}

impl AsyncWrite for Channel<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream(0)).poll_write(cx, src)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream(0)).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_close(cx)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }
}

/// The stream associated with a `Channel`.
pub struct Stream<'a, 'sess> {
    channel: &'a mut Channel<'sess>,
    stream_id: i32,
}

impl AsyncRead for Stream<'_, '_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        dst: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        me.channel
            .poll_read(cx, me.stream_id, dst)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }
}

impl AsyncWrite for Stream<'_, '_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        me.channel
            .poll_write(cx, me.stream_id, src)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.channel
            .poll_flush(cx, me.stream_id)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
