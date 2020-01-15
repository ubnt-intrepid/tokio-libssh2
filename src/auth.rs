//! Authentication of a session.

use crate::{error::Result, session::Session};
use futures::task::{self, Poll};
use libssh2_sys as sys;
use std::pin::Pin;

pub trait Authenticator {
    fn poll_authenticate(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        auth: &mut AuthContext<'_>,
    ) -> Poll<Result<()>>;
}

pub struct AuthContext<'auth> {
    pub(crate) sess: &'auth mut Session,
    pub(crate) username: &'auth str,
}

/// An `Authenticator` using the password.
pub struct PasswordAuth<T: AsRef<str>> {
    password: T,
}

impl<T: AsRef<str>> Authenticator for PasswordAuth<T> {
    fn poll_authenticate(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        auth: &mut AuthContext<'_>,
    ) -> Poll<Result<()>> {
        let username = auth.username;
        let password = self.password.as_ref();
        auth.sess.poll_with(cx, |sess| {
            let rc = unsafe {
                sys::libssh2_userauth_password_ex(
                    sess.as_raw_ptr(),
                    username.as_ptr() as *const libc::c_char,
                    username.len() as libc::c_uint,
                    password.as_ptr() as *const libc::c_char,
                    password.len() as libc::c_uint,
                    None,
                )
            };
            sess.rc(rc).map(drop)
        })
    }
}

/// Create a `PasswordAuth` with the provided password string.
pub fn password<T: AsRef<str>>(password: T) -> PasswordAuth<T> {
    PasswordAuth { password }
}
