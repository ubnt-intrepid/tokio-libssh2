use libssh2_sys as sys;
use std::{borrow::Cow, error, fmt, io, ptr};

#[derive(Debug)]
pub struct Ssh2Error {
    code: libc::c_int,
    msg: Cow<'static, str>,
}

impl fmt::Display for Ssh2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (code = {})", self.message(), self.code())
    }
}

impl error::Error for Ssh2Error {}

impl Ssh2Error {
    pub(crate) fn new(code: libc::c_int, msg: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            msg: msg.into(),
        }
    }

    pub(crate) unsafe fn last_error(sess: *mut sys::LIBSSH2_SESSION) -> Option<Self> {
        let mut errmsg = ptr::null_mut();
        let mut errmsg_len = 0;

        let code = sys::libssh2_session_last_error(sess, &mut errmsg, &mut errmsg_len, 0);
        if code == 0 {
            return None;
        }

        let msg = std::slice::from_raw_parts(errmsg as *const u8, errmsg_len as usize);
        let msg = String::from_utf8_lossy(msg).into_owned();

        Some(Self::new(code, msg))
    }

    pub(crate) fn unknown() -> Self {
        Self::new(libc::c_int::min_value(), "unknown error")
    }

    pub(crate) fn from_code(code: libc::c_int) -> Self {
        let msg = match code {
            sys::LIBSSH2_ERROR_BANNER_RECV => "banner recv failure",
            sys::LIBSSH2_ERROR_BANNER_SEND => "banner send failure",
            sys::LIBSSH2_ERROR_INVALID_MAC => "invalid mac",
            sys::LIBSSH2_ERROR_KEX_FAILURE => "kex failure",
            sys::LIBSSH2_ERROR_ALLOC => "alloc failure",
            sys::LIBSSH2_ERROR_SOCKET_SEND => "socket send faiulre",
            sys::LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE => "key exchange failure",
            sys::LIBSSH2_ERROR_TIMEOUT => "timed out",
            sys::LIBSSH2_ERROR_HOSTKEY_INIT => "hostkey init error",
            sys::LIBSSH2_ERROR_HOSTKEY_SIGN => "hostkey sign error",
            sys::LIBSSH2_ERROR_DECRYPT => "decrypt error",
            sys::LIBSSH2_ERROR_SOCKET_DISCONNECT => "socket disconnected",
            sys::LIBSSH2_ERROR_PROTO => "protocol error",
            sys::LIBSSH2_ERROR_PASSWORD_EXPIRED => "password expired",
            sys::LIBSSH2_ERROR_FILE => "file error",
            sys::LIBSSH2_ERROR_METHOD_NONE => "bad method name",
            sys::LIBSSH2_ERROR_AUTHENTICATION_FAILED => "authentication failed",
            sys::LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED => "public key unverified",
            sys::LIBSSH2_ERROR_CHANNEL_OUTOFORDER => "channel out of order",
            sys::LIBSSH2_ERROR_CHANNEL_FAILURE => "channel failure",
            sys::LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED => "request denied",
            sys::LIBSSH2_ERROR_CHANNEL_UNKNOWN => "unknown channel error",
            sys::LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED => "window exceeded",
            sys::LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED => "packet exceeded",
            sys::LIBSSH2_ERROR_CHANNEL_CLOSED => "closed channel",
            sys::LIBSSH2_ERROR_CHANNEL_EOF_SENT => "eof sent",
            sys::LIBSSH2_ERROR_SCP_PROTOCOL => "scp protocol error",
            sys::LIBSSH2_ERROR_ZLIB => "zlib error",
            sys::LIBSSH2_ERROR_SOCKET_TIMEOUT => "socket timeout",
            sys::LIBSSH2_ERROR_SFTP_PROTOCOL => "sftp protocol error",
            sys::LIBSSH2_ERROR_REQUEST_DENIED => "request denied",
            sys::LIBSSH2_ERROR_METHOD_NOT_SUPPORTED => "method not supported",
            sys::LIBSSH2_ERROR_INVAL => "invalid",
            sys::LIBSSH2_ERROR_INVALID_POLL_TYPE => "invalid poll type",
            sys::LIBSSH2_ERROR_PUBLICKEY_PROTOCOL => "public key protocol error",
            sys::LIBSSH2_ERROR_EAGAIN => "operation would block",
            sys::LIBSSH2_ERROR_BUFFER_TOO_SMALL => "buffer too small",
            sys::LIBSSH2_ERROR_BAD_USE => "bad use error",
            sys::LIBSSH2_ERROR_COMPRESS => "compression error",
            sys::LIBSSH2_ERROR_OUT_OF_BOUNDARY => "out of bounds",
            sys::LIBSSH2_ERROR_AGENT_PROTOCOL => "invalid agent protocol",
            sys::LIBSSH2_ERROR_SOCKET_RECV => "error receiving on socket",
            sys::LIBSSH2_ERROR_ENCRYPT => "bad encrypt",
            sys::LIBSSH2_ERROR_BAD_SOCKET => "bad socket",
            sys::LIBSSH2_ERROR_KNOWN_HOSTS => "known hosts error",
            sys::LIBSSH2_FX_EOF => "end of file",
            sys::LIBSSH2_FX_NO_SUCH_FILE => "no such file",
            sys::LIBSSH2_FX_PERMISSION_DENIED => "permission denied",
            sys::LIBSSH2_FX_FAILURE => "failure",
            sys::LIBSSH2_FX_BAD_MESSAGE => "bad message",
            sys::LIBSSH2_FX_NO_CONNECTION => "no connection",
            sys::LIBSSH2_FX_CONNECTION_LOST => "connection lost",
            sys::LIBSSH2_FX_OP_UNSUPPORTED => "operation unsupported",
            sys::LIBSSH2_FX_INVALID_HANDLE => "invalid handle",
            sys::LIBSSH2_FX_NO_SUCH_PATH => "no such path",
            sys::LIBSSH2_FX_FILE_ALREADY_EXISTS => "file already exists",
            sys::LIBSSH2_FX_WRITE_PROTECT => "file is write protected",
            sys::LIBSSH2_FX_NO_MEDIA => "no media available",
            sys::LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM => "no space on filesystem",
            sys::LIBSSH2_FX_QUOTA_EXCEEDED => "quota exceeded",
            sys::LIBSSH2_FX_UNKNOWN_PRINCIPAL => "unknown principal",
            sys::LIBSSH2_FX_LOCK_CONFLICT => "lock conflict",
            sys::LIBSSH2_FX_DIR_NOT_EMPTY => "directory not empty",
            sys::LIBSSH2_FX_NOT_A_DIRECTORY => "not a directory",
            sys::LIBSSH2_FX_INVALID_FILENAME => "invalid filename",
            sys::LIBSSH2_FX_LINK_LOOP => "link loop",
            _ => return Self::unknown(),
        };
        Self::new(code, msg)
    }

    pub fn code(&self) -> libc::c_int {
        self.code
    }

    pub fn message(&self) -> &str {
        &*self.msg
    }
}

#[derive(Debug)]
pub struct Error(ErrorKind);

#[derive(Debug)]
enum ErrorKind {
    Io(io::Error),
    Ssh2(Ssh2Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ErrorKind::Io(ref err) => write!(f, "I/O error: {}", err),
            ErrorKind::Ssh2(ref err) => write!(f, "libssh2 error: {}", err),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.0 {
            ErrorKind::Io(ref err) => Some(err),
            ErrorKind::Ssh2(ref err) => Some(err),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self(ErrorKind::Io(err))
    }
}

impl From<Ssh2Error> for Error {
    fn from(err: Ssh2Error) -> Self {
        Self(ErrorKind::Ssh2(err))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
