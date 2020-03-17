use std::{
    borrow::Cow,
    cmp, fmt, marker,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{
    io::{self, AsyncRead},
};
use std::path::{Path};

use pin_project::{pin_project, project};

use crate::{
    header::bytes2path, pax::pax_extensions, Archive, Header, PaxExtensions,
};

/// A read-only view into an entry of an archive.
///
/// This structure is a window into a portion of a borrowed archive which can
/// be inspected. It acts as a file handle by implementing the Reader trait. An
/// entry cannot be rewritten once inserted into an archive.
#[pin_project]
pub struct Entry<R: AsyncRead + Unpin> {
    #[pin]
    fields: EntryFields<R>,
    _ignored: marker::PhantomData<Archive<R>>,
}

impl<R: AsyncRead + Unpin> fmt::Debug for Entry<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("fields", &self.fields)
            .finish()
    }
}

// private implementation detail of `Entry`, but concrete (no type parameters)
// and also all-public to be constructed from other modules.
#[pin_project]
pub struct EntryFields<R: AsyncRead + Unpin> {
    pub long_pathname: Option<Vec<u8>>,
    pub long_linkname: Option<Vec<u8>>,
    pub pax_extensions: Option<Vec<u8>>,
    pub header: Header,
    pub size: u64,
    pub header_pos: u64,
    pub file_pos: u64,
    #[pin]
    pub data: Vec<EntryIo<R>>,
    pub unpack_xattrs: bool,
    pub preserve_permissions: bool,
    pub preserve_mtime: bool,
    #[pin]
    pub(crate) read_state: Option<EntryIo<R>>,
}

impl<R: AsyncRead + Unpin> fmt::Debug for EntryFields<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryFields")
            .field("long_pathname", &self.long_pathname)
            .field("long_linkname", &self.long_linkname)
            .field("pax_extensions", &self.pax_extensions)
            .field("header", &self.header)
            .field("size", &self.size)
            .field("header_pos", &self.header_pos)
            .field("file_pos", &self.file_pos)
            .field("data", &self.data)
            .field("unpack_xattrs", &self.unpack_xattrs)
            .field("preserve_permissions", &self.preserve_permissions)
            .field("preserve_mtime", &self.preserve_mtime)
            .field("read_state", &self.read_state)
            .finish()
    }
}

#[pin_project]
pub enum EntryIo<R: AsyncRead + Unpin> {
    Pad(#[pin] io::Take<io::Repeat>),
    Data(#[pin] io::Take<R>),
}

impl<R: AsyncRead + Unpin> fmt::Debug for EntryIo<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntryIo::Pad(_) => write!(f, "EntryIo::Pad"),
            EntryIo::Data(_) => write!(f, "EntryIo::Data"),
        }
    }
}

impl<R: AsyncRead + Unpin> Entry<R> {
    /// Returns the path name for this entry.
    ///
    /// This method may fail if the pathname is not valid Unicode and this is
    /// called on a Windows platform.
    ///
    /// Note that this function will convert any `\` characters to directory
    /// separators, and it will not always return the same value as
    /// `self.header().path()` as some archive formats have support for longer
    /// path names described in separate entries.
    ///
    /// It is recommended to use this method instead of inspecting the `header`
    /// directly to ensure that various archive formats are handled correctly.
    pub fn path(&self) -> io::Result<Cow<Path>> {
        self.fields.path()
    }

    /// Returns the raw bytes listed for this entry.
    ///
    /// Note that this function will convert any `\` characters to directory
    /// separators, and it will not always return the same value as
    /// `self.header().path_bytes()` as some archive formats have support for
    /// longer path names described in separate entries.
    pub fn path_bytes(&self) -> Cow<[u8]> {
        self.fields.path_bytes()
    }

    /// Returns the link name for this entry, if any is found.
    ///
    /// This method may fail if the pathname is not valid Unicode and this is
    /// called on a Windows platform. `Ok(None)` being returned, however,
    /// indicates that the link name was not present.
    ///
    /// Note that this function will convert any `\` characters to directory
    /// separators, and it will not always return the same value as
    /// `self.header().link_name()` as some archive formats have support for
    /// longer path names described in separate entries.
    ///
    /// It is recommended to use this method instead of inspecting the `header`
    /// directly to ensure that various archive formats are handled correctly.
    pub fn link_name(&self) -> io::Result<Option<Cow<Path>>> {
        self.fields.link_name()
    }

    /// Returns the link name for this entry, in bytes, if listed.
    ///
    /// Note that this will not always return the same value as
    /// `self.header().link_name_bytes()` as some archive formats have support for
    /// longer path names described in separate entries.
    pub fn link_name_bytes(&self) -> Option<Cow<[u8]>> {
        self.fields.link_name_bytes()
    }

    /// Returns an iterator over the pax extensions contained in this entry.
    ///
    /// Pax extensions are a form of archive where extra metadata is stored in
    /// key/value pairs in entries before the entry they're intended to
    /// describe. For example this can be used to describe long file name or
    /// other metadata like atime/ctime/mtime in more precision.
    ///
    /// The returned iterator will yield key/value pairs for each extension.
    ///
    /// `None` will be returned if this entry does not indicate that it itself
    /// contains extensions, or if there were no previous extensions describing
    /// it.
    ///
    /// Note that global pax extensions are intended to be applied to all
    /// archive entries.
    ///
    /// Also note that this function will read the entire entry if the entry
    /// itself is a list of extensions.
    pub async fn pax_extensions(&mut self) -> io::Result<Option<PaxExtensions<'_>>> {
        self.fields.pax_extensions().await
    }

    /// Returns access to the header of this entry in the archive.
    ///
    /// This provides access to the metadata for this entry in the archive.
    pub fn header(&self) -> &Header {
        &self.fields.header
    }

    /// Returns the starting position, in bytes, of the header of this entry in
    /// the archive.
    ///
    /// The header is always a contiguous section of 512 bytes, so if the
    /// underlying reader implements `Seek`, then the slice from `header_pos` to
    /// `header_pos + 512` contains the raw header bytes.
    pub fn raw_header_position(&self) -> u64 {
        self.fields.header_pos
    }

    /// Returns the starting position, in bytes, of the file of this entry in
    /// the archive.
    ///
    /// If the file of this entry is continuous (e.g. not a sparse file), and
    /// if the underlying reader implements `Seek`, then the slice from
    /// `file_pos` to `file_pos + entry_size` contains the raw file bytes.
    pub fn raw_file_position(&self) -> u64 {
        self.fields.file_pos
    }

    /// Indicate whether extended file attributes (xattrs on Unix) are preserved
    /// when unpacking this entry.
    ///
    /// This flag is disabled by default and is currently only implemented on
    /// Unix using xattr support. This may eventually be implemented for
    /// Windows, however, if other archive implementations are found which do
    /// this as well.
    pub fn set_unpack_xattrs(&mut self, unpack_xattrs: bool) {
        self.fields.unpack_xattrs = unpack_xattrs;
    }

    /// Indicate whether extended permissions (like suid on Unix) are preserved
    /// when unpacking this entry.
    ///
    /// This flag is disabled by default and is currently only implemented on
    /// Unix.
    pub fn set_preserve_permissions(&mut self, preserve: bool) {
        self.fields.preserve_permissions = preserve;
    }

    /// Indicate whether access time information is preserved when unpacking
    /// this entry.
    ///
    /// This flag is enabled by default.
    pub fn set_preserve_mtime(&mut self, preserve: bool) {
        self.fields.preserve_mtime = preserve;
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Entry<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        into: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        Pin::new(&mut *this.fields).poll_read(cx, into)
    }
}

impl<R: AsyncRead + Unpin> EntryFields<R> {
    pub fn from(entry: Entry<R>) -> Self {
        entry.fields
    }

    pub fn into_entry(self) -> Entry<R> {
        Entry {
            fields: self,
            _ignored: marker::PhantomData,
        }
    }

    pub(crate) fn poll_read_all(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Vec<u8>>> {
        // Preallocate some data but don't let ourselves get too crazy now.
        let cap = cmp::min(self.size, 128 * 1024);
        let mut buf = Vec::with_capacity(cap as usize);

        // Copied from futures::ReadToEnd
        match futures::ready!(poll_read_all_internal(self, cx, &mut buf)) {
            Ok(_) => Poll::Ready(Ok(buf)),
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    pub async fn read_all(&mut self) -> io::Result<Vec<u8>> {
        use futures::io::AsyncReadExt;
        // Preallocate some data but don't let ourselves get too crazy now.
        let cap = cmp::min(self.size, 128 * 1024);
        let mut v = Vec::with_capacity(cap as usize);
        self.read_to_end(&mut v).await.map(|_| v)
    }

    fn path(&self) -> io::Result<Cow<'_, Path>> {
        bytes2path(self.path_bytes())
    }

    fn path_bytes(&self) -> Cow<[u8]> {
        match self.long_pathname {
            Some(ref bytes) => {
                if let Some(&0) = bytes.last() {
                    Cow::Borrowed(&bytes[..bytes.len() - 1])
                } else {
                    Cow::Borrowed(bytes)
                }
            }
            None => {
                if let Some(ref pax) = self.pax_extensions {
                    let pax = pax_extensions(pax)
                        .filter_map(|f| f.ok())
                        .find(|f| f.key_bytes() == b"path")
                        .map(|f| f.value_bytes());
                    if let Some(field) = pax {
                        return Cow::Borrowed(field);
                    }
                }
                self.header.path_bytes()
            }
        }
    }

    fn link_name(&self) -> io::Result<Option<Cow<Path>>> {
        match self.link_name_bytes() {
            Some(bytes) => bytes2path(bytes).map(Some),
            None => Ok(None),
        }
    }

    fn link_name_bytes(&self) -> Option<Cow<[u8]>> {
        match self.long_linkname {
            Some(ref bytes) => {
                if let Some(&0) = bytes.last() {
                    Some(Cow::Borrowed(&bytes[..bytes.len() - 1]))
                } else {
                    Some(Cow::Borrowed(bytes))
                }
            }
            None => self.header.link_name_bytes(),
        }
    }

    async fn pax_extensions(&mut self) -> io::Result<Option<PaxExtensions<'_>>> {
        if self.pax_extensions.is_none() {
            if !self.header.entry_type().is_pax_global_extensions()
                && !self.header.entry_type().is_pax_local_extensions()
            {
                return Ok(None);
            }
            self.pax_extensions = Some(self.read_all().await?);
        }
        Ok(Some(pax_extensions(self.pax_extensions.as_ref().unwrap())))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for EntryFields<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        into: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        loop {
            if this.read_state.is_none() {
                if this.data.as_ref().is_empty() {
                    *this.read_state = None;
                } else {
                    let data = &mut *this.data;
                    *this.read_state = Some(data.remove(0));
                }
            }

            if let Some(ref mut io) = &mut *this.read_state {
                let ret = Pin::new(io).poll_read(cx, into);
                match ret {
                    Poll::Ready(Ok(0)) => {
                        *this.read_state = None;
                        if this.data.as_ref().is_empty() {
                            return Poll::Ready(Ok(0));
                        }
                        continue;
                    }
                    Poll::Ready(Ok(val)) => {
                        return Poll::Ready(Ok(val));
                    }
                    Poll::Ready(Err(err)) => {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            } else {
                // Unable to pull another value from `data`, so we are done.
                return Poll::Ready(Ok(0));
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for EntryIo<R> {
    #[project]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        into: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        #[project]
        match self.project() {
            EntryIo::Pad(io) => io.poll_read(cx, into),
            EntryIo::Data(io) => io.poll_read(cx, into),
        }
    }
}

struct Guard<'a> {
    buf: &'a mut Vec<u8>,
    len: usize,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        unsafe {
            self.buf.set_len(self.len);
        }
    }
}

fn poll_read_all_internal<R: AsyncRead + ?Sized>(
    mut rd: Pin<&mut R>,
    cx: &mut Context<'_>,
    buf: &mut Vec<u8>,
) -> Poll<io::Result<usize>> {
    let mut g = Guard {
        len: buf.len(),
        buf,
    };
    let ret;
    loop {
        if g.len == g.buf.len() {
            unsafe {
                g.buf.reserve(32);
                let capacity = g.buf.capacity();
                g.buf.set_len(capacity);

                let buf = &mut g.buf[g.len..];
                std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len());
            }
        }

        match futures::ready!(rd.as_mut().poll_read(cx, &mut g.buf[g.len..])) {
            Ok(0) => {
                ret = Poll::Ready(Ok(g.len));
                break;
            }
            Ok(n) => g.len += n,
            Err(e) => {
                ret = Poll::Ready(Err(e));
                break;
            }
        }
    }

    ret
}
