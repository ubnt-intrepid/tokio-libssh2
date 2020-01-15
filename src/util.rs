use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

#[cfg(unix)]
pub(crate) fn path_to_bytes<'a>(path: &'a Path) -> crate::Result<Cow<'a, [u8]>> {
    use std::io;
    use std::os::unix::prelude::*;

    let path = path.as_os_str().as_bytes();
    if path.contains(&b'\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unexpected null character in a path",
        )
        .into());
    }

    Ok(Cow::Borrowed(path))
}

#[cfg(windows)]
pub(crate) fn path_to_bytes<'a>(path: &'a Path) -> crate::Result<Cow<'a, [u8]>> {
    let path = path
        .to_str() //
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidArgument,
                "only unicode paths on windows may be used",
            )
        })?
        .as_bytes();

    let path;
    if path.contains(&b'\\') {
        // Normalize to Unix-style path separators
        let mut path = path.to_owned();
        for b in &mut path {
            if *b == b'\\' {
                *b = b'/';
            }
        }
        path = Cow::Owned(path);
    } else {
        path = Cow::Borrowed(bytes);
    }

    if path.iter().contains(|b| b == b'\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidArgument,
            "unexpected null character in a path",
        )
        .into());
    }

    Ok(path)
}

#[cfg(unix)]
pub(crate) fn bytes_to_path(bytes: Vec<u8>) -> crate::Result<PathBuf> {
    use std::os::unix::prelude::*;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(windows)]
pub(crate) fn bytes_to_path(bytes: Vec<u8>) -> crate::Result<PathBuf> {
    let path = String::from_utf8(bytes) //
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(PathBuf::from(path))
}
