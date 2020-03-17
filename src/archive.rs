use std::{
    cell::{Cell, RefCell},
    cmp,
    pin::Pin,
};

use futures::{
    io,
    prelude::*,
    stream::Stream,
    task::{Context, Poll},
};

use std::sync::Arc;

use pin_project::pin_project;

use crate::pin_cell::PinCell;

use crate::{
    entry::{EntryFields, EntryIo},
    other, Entry, GnuExtSparseHeader, GnuSparseHeader, Header,
};

/// A top-level representation of an archive file.
///
/// This archive can have an entry added to it and it can be iterated over.
#[derive(Debug)]
pub struct Archive<R: AsyncRead + Unpin> {
    inner: Arc<ArchiveInner<R>>,
}

impl<R: AsyncRead + Unpin> Clone for Archive<R> {
    fn clone(&self) -> Self {
        Archive {
            inner: self.inner.clone(),
        }
    }
}

#[pin_project]
#[derive(Debug)]
pub struct ArchiveInner<R> {
    pos: Cell<u64>,
    unpack_xattrs: bool,
    preserve_permissions: bool,
    preserve_mtime: bool,
    ignore_zeros: bool,
    #[pin]
    obj: PinCell<R>,
}

/// Configure the archive.
pub struct ArchiveBuilder<R: AsyncRead + Unpin> {
    obj: PinCell<R>,
    unpack_xattrs: bool,
    preserve_permissions: bool,
    preserve_mtime: bool,
    ignore_zeros: bool,
}

impl<R: AsyncRead + Unpin> ArchiveBuilder<R> {
    /// Create a new builder.
    pub fn new(obj: R) -> Self {
        ArchiveBuilder {
            unpack_xattrs: false,
            preserve_permissions: false,
            preserve_mtime: true,
            ignore_zeros: false,
            obj: PinCell::new(obj),
        }
    }

    /// Indicate whether extended file attributes (xattrs on Unix) are preserved
    /// when unpacking this archive.
    ///
    /// This flag is disabled by default and is currently only implemented on
    /// Unix using xattr support. This may eventually be implemented for
    /// Windows, however, if other archive implementations are found which do
    /// this as well.
    pub fn set_unpack_xattrs(mut self, unpack_xattrs: bool) -> Self {
        self.unpack_xattrs = unpack_xattrs;
        self
    }

    /// Indicate whether extended permissions (like suid on Unix) are preserved
    /// when unpacking this entry.
    ///
    /// This flag is disabled by default and is currently only implemented on
    /// Unix.
    pub fn set_preserve_permissions(mut self, preserve: bool) -> Self {
        self.preserve_permissions = preserve;
        self
    }

    /// Indicate whether access time information is preserved when unpacking
    /// this entry.
    ///
    /// This flag is enabled by default.
    pub fn set_preserve_mtime(mut self, preserve: bool) -> Self {
        self.preserve_mtime = preserve;
        self
    }

    /// Ignore zeroed headers, which would otherwise indicate to the archive that it has no more
    /// entries.
    ///
    /// This can be used in case multiple tar archives have been concatenated together.
    pub fn set_ignore_zeros(mut self, ignore_zeros: bool) -> Self {
        self.ignore_zeros = ignore_zeros;
        self
    }

    /// Construct the archive, ready to accept inputs.
    pub fn build(self) -> Archive<R> {
        let Self {
            unpack_xattrs,
            preserve_permissions,
            preserve_mtime,
            ignore_zeros,
            obj,
        } = self;

        Archive {
            inner: Arc::new(ArchiveInner {
                unpack_xattrs,
                preserve_permissions,
                preserve_mtime,
                ignore_zeros,
                obj,
                pos: Cell::new(0),
            }),
        }
    }
}

impl<R: AsyncRead + Unpin + Sync + Send> Archive<R> {
    /// Create a new archive with the underlying object as the reader.
    pub fn new(obj: R) -> Archive<R> {
        Archive {
            inner: Arc::new(ArchiveInner {
                unpack_xattrs: false,
                preserve_permissions: false,
                preserve_mtime: true,
                ignore_zeros: false,
                obj: PinCell::new(obj),
                pos: Cell::new(0),
            }),
        }
    }

    /// Unwrap this archive, returning the underlying object.
    pub fn into_inner(self) -> Result<R, Self> {
        let Self { inner } = self;

        match Arc::try_unwrap(inner) {
            Ok(inner) => {
                let c: RefCell<R> = inner.obj.into();
                Ok(c.into_inner())
            }
            Err(inner) => Err(Self { inner }),
        }
    }

    /// Construct an stream over the entries in this archive.
    ///
    /// Note that care must be taken to consider each entry within an archive in
    /// sequence. If entries are processed out of sequence (from what the
    /// stream returns), then the contents read for each entry may be
    /// corrupted.
    pub fn entries(&mut self) -> io::Result<Entries<R>> {
        if self.inner.pos.get() != 0 {
            return Err(other(
                "cannot call entries unless archive is at \
                 position 0",
            ));
        }

        Ok(Entries {
            archive: self.clone(),
            next: 0,
            gnu_longlink: None,
            gnu_longname: None,
            pax_extensions: None,
        })
    }

    /// Construct an stream over the raw entries in this archive.
    ///
    /// Note that care must be taken to consider each entry within an archive in
    /// sequence. If entries are processed out of sequence (from what the
    /// stream returns), then the contents read for each entry may be
    /// corrupted.
    pub fn entries_raw(&mut self) -> io::Result<RawEntries<R>> {
        if self.inner.pos.get() != 0 {
            return Err(other(
                "cannot call entries_raw unless archive is at \
                 position 0",
            ));
        }

        Ok(RawEntries {
            archive: self.clone(),
            next: 0,
        })
    }
}

/// Stream of `Entry`s.
pub struct Entries<R: AsyncRead + Unpin> {
    archive: Archive<R>,
    next: u64,
    gnu_longname: Option<Vec<u8>>,
    gnu_longlink: Option<Vec<u8>>,
    pax_extensions: Option<Vec<u8>>,
}

macro_rules! ready_opt_err {
    ($val:expr) => {
        match futures::ready!($val) {
            Some(Ok(val)) => val,
            Some(Err(err)) => return Poll::Ready(Some(Err(err))),
            None => return Poll::Ready(None),
        }
    };
}

macro_rules! ready_err {
    ($val:expr) => {
        match futures::ready!($val) {
            Ok(val) => val,
            Err(err) => return Poll::Ready(Some(Err(err))),
        }
    };
}

impl<R: AsyncRead + Unpin> Stream for Entries<R> {
    type Item = io::Result<Entry<Archive<R>>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let entry = ready_opt_err!(poll_next_raw(self.archive.clone(), &mut self.next, cx));

            if entry.header().as_gnu().is_some() && entry.header().entry_type().is_gnu_longname() {
                if self.gnu_longname.is_some() {
                    return Poll::Ready(Some(Err(other(
                        "two long name entries describing \
                         the same member",
                    ))));
                }

                let mut ef = EntryFields::from(entry);
                let val = ready_err!(Pin::new(&mut ef).poll_read_all(cx));
                self.gnu_longname = Some(val);
                continue;
            }

            if entry.header().as_gnu().is_some() && entry.header().entry_type().is_gnu_longlink() {
                if self.gnu_longlink.is_some() {
                    return Poll::Ready(Some(Err(other(
                        "two long name entries describing \
                         the same member",
                    ))));
                }
                let mut ef = EntryFields::from(entry);
                let val = ready_err!(Pin::new(&mut ef).poll_read_all(cx));
                self.gnu_longlink = Some(val);
                continue;
            }

            if entry.header().as_ustar().is_some()
                && entry.header().entry_type().is_pax_local_extensions()
            {
                if self.pax_extensions.is_some() {
                    return Poll::Ready(Some(Err(other(
                        "two pax extensions entries describing \
                         the same member",
                    ))));
                }
                let mut ef = EntryFields::from(entry);
                let val = ready_err!(Pin::new(&mut ef).poll_read_all(cx));
                self.pax_extensions = Some(val);
                continue;
            }

            let mut fields = EntryFields::from(entry);
            fields.long_pathname = self.gnu_longname.take();
            fields.long_linkname = self.gnu_longlink.take();
            fields.pax_extensions = self.pax_extensions.take();

            ready_err!(poll_parse_sparse_header(
                self.archive.clone(),
                &mut self.next,
                &mut fields,
                cx
            ));

            return Poll::Ready(Some(Ok(fields.into_entry())));
        }
    }
}

/// Stream of raw `Entry`s.
pub struct RawEntries<R: AsyncRead + Unpin> {
    archive: Archive<R>,
    next: u64,
}

impl<R: AsyncRead + Unpin> Stream for RawEntries<R> {
    type Item = io::Result<Entry<Archive<R>>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        poll_next_raw(self.archive.clone(), &mut self.next, cx)
    }
}

fn poll_next_raw<R: AsyncRead + Unpin>(
    mut archive: Archive<R>,
    next: &mut u64,
    cx: &mut Context<'_>,
) -> Poll<Option<io::Result<Entry<Archive<R>>>>> {
    let mut header = Header::new_old();
    let mut header_pos = *next;

    loop {
        // Seek to the start of the next header in the archive
        let delta = *next - archive.inner.pos.get();

        match futures::ready!(poll_skip(&mut archive, cx, delta)) {
            Ok(_) => {}
            Err(err) => return Poll::Ready(Some(Err(err))),
        }

        // EOF is an indicator that we are at the end of the archive.
        match futures::ready!(poll_try_read_all(&mut archive, cx, header.as_mut_bytes())) {
            Ok(true) => {}
            Ok(false) => return Poll::Ready(None),
            Err(err) => return Poll::Ready(Some(Err(err))),
        }

        // If a header is not all zeros, we have another valid header.
        // Otherwise, check if we are ignoring zeros and continue, or break as if this is the
        // end of the archive.
        if !header.as_bytes().iter().all(|i| *i == 0) {
            *next += 512;
            break;
        }

        if !archive.inner.ignore_zeros {
            return Poll::Ready(None);
        }

        *next += 512;
        header_pos = *next;
    }

    // Make sure the checksum is ok
    let sum = header.as_bytes()[..148]
        .iter()
        .chain(&header.as_bytes()[156..])
        .fold(0, |a, b| a + (*b as u32))
        + 8 * 32;
    let cksum = header.cksum()?;
    if sum != cksum {
        return Poll::Ready(Some(Err(other("archive header checksum mismatch"))));
    }

    let file_pos = *next;
    let size = header.entry_size()?;

    let data = EntryIo::Data(archive.clone().take(size));

    let ret = EntryFields {
        size,
        header_pos,
        file_pos,
        data: vec![data],
        header,
        long_pathname: None,
        long_linkname: None,
        pax_extensions: None,
        unpack_xattrs: archive.inner.unpack_xattrs,
        preserve_permissions: archive.inner.preserve_permissions,
        preserve_mtime: archive.inner.preserve_mtime,
        read_state: None,
    };

    // Store where the next entry is, rounding up by 512 bytes (the size of
    // a header);
    let size = (size + 511) & !(512 - 1);
    *next += size;

    Poll::Ready(Some(Ok(ret.into_entry())))
}

fn poll_parse_sparse_header<R: AsyncRead + Unpin>(
    mut archive: Archive<R>,
    next: &mut u64,
    entry: &mut EntryFields<Archive<R>>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    if !entry.header.entry_type().is_gnu_sparse() {
        return Poll::Ready(Ok(()));
    }

    let gnu = match entry.header.as_gnu() {
        Some(gnu) => gnu,
        None => return Poll::Ready(Err(other("sparse entry type listed but not GNU header"))),
    };

    // Sparse files are represented internally as a list of blocks that are
    // read. Blocks are either a bunch of 0's or they're data from the
    // underlying archive.
    //
    // Blocks of a sparse file are described by the `GnuSparseHeader`
    // structure, some of which are contained in `GnuHeader` but some of
    // which may also be contained after the first header in further
    // headers.
    //
    // We read off all the blocks here and use the `add_block` function to
    // incrementally add them to the list of I/O block (in `entry.data`).
    // The `add_block` function also validates that each chunk comes after
    // the previous, we don't overrun the end of the file, and each block is
    // aligned to a 512-byte boundary in the archive itself.
    //
    // At the end we verify that the sparse file size (`Header::size`) is
    // the same as the current offset (described by the list of blocks) as
    // well as the amount of data read equals the size of the entry
    // (`Header::entry_size`).
    entry.data.truncate(0);

    let mut cur = 0;
    let mut remaining = entry.size;
    {
        let data = &mut entry.data;
        let reader = archive.clone();
        let size = entry.size;
        let mut add_block = |block: &GnuSparseHeader| -> io::Result<_> {
            if block.is_empty() {
                return Ok(());
            }
            let off = block.offset()?;
            let len = block.length()?;

            if (size - remaining) % 512 != 0 {
                return Err(other(
                    "previous block in sparse file was not \
                     aligned to 512-byte boundary",
                ));
            } else if off < cur {
                return Err(other(
                    "out of order or overlapping sparse \
                     blocks",
                ));
            } else if cur < off {
                let block = io::repeat(0).take(off - cur);
                data.push(EntryIo::Pad(block));
            }
            cur = off
                .checked_add(len)
                .ok_or_else(|| other("more bytes listed in sparse file than u64 can hold"))?;
            remaining = remaining.checked_sub(len).ok_or_else(|| {
                other(
                    "sparse file consumed more data than the header \
                     listed",
                )
            })?;
            data.push(EntryIo::Data(reader.clone().take(len)));
            Ok(())
        };
        for block in gnu.sparse.iter() {
            add_block(block)?
        }
        if gnu.is_extended() {
            let mut ext = GnuExtSparseHeader::new();
            ext.isextended[0] = 1;
            while ext.is_extended() {
                match futures::ready!(poll_try_read_all(
                    &mut archive,
                    cx,
                    ext.as_mut_bytes()
                )) {
                    Ok(true) => {}
                    Ok(false) => return Poll::Ready(Err(other("failed to read extension"))),
                    Err(err) => return Poll::Ready(Err(err)),
                }

                *next += 512;
                for block in ext.sparse.iter() {
                    add_block(block)?;
                }
            }
        }
    }
    if cur != gnu.real_size()? {
        return Poll::Ready(Err(other(
            "mismatch in sparse file chunks and \
             size in header",
        )));
    }
    entry.size = cur;
    if remaining > 0 {
        return Poll::Ready(Err(other(
            "mismatch in sparse file chunks and \
             entry size in header",
        )));
    }

    Poll::Ready(Ok(()))
}

impl<R: AsyncRead + Unpin> AsyncRead for Archive<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        into: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut r = Pin::new(&Pin::new(&mut &*self.inner).obj).borrow_mut();

        let res =
            futures::ready!(crate::pin_cell::PinMut::as_mut(&mut r).poll_read(cx, into));
        match res {
            Ok(i) => {
                self.inner.pos.set(self.inner.pos.get() + i as u64);
                Poll::Ready(Ok(i))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

/// Try to fill the buffer from the reader.
///
/// If the reader reaches its end before filling the buffer at all, returns `false`.
/// Otherwise returns `true`.
fn poll_try_read_all<R: AsyncRead + Unpin>(
    mut source: R,
    cx: &mut Context<'_>,
    buf: &mut [u8],
) -> Poll<io::Result<bool>> {
    let mut read = 0;
    while read < buf.len() {
        match futures::ready!(Pin::new(&mut source).poll_read(cx, &mut buf[read..])) {
            Ok(0) => {
                if read == 0 {
                    return Poll::Ready(Ok(false));
                }

                return Poll::Ready(Err(other("failed to read entire block")));
            }
            Ok(n) => read += n,
            Err(err) => return Poll::Ready(Err(err)),
        }
    }

    Poll::Ready(Ok(true))
}

/// Skip n bytes on the given source.
fn poll_skip<R: AsyncRead + Unpin>(
    mut source: R,
    cx: &mut Context<'_>,
    mut amt: u64,
) -> Poll<io::Result<()>> {
    let mut buf = [0u8; 4096 * 8];
    while amt > 0 {
        let n = cmp::min(amt, buf.len() as u64);
        match futures::ready!(Pin::new(&mut source).poll_read(cx, &mut buf[..n as usize])) {
            Ok(n) if n == 0 => {
                return Poll::Ready(Err(other("unexpected EOF during skip")));
            }
            Ok(n) => {
                amt -= n as u64;
            }
            Err(err) => return Poll::Ready(Err(err)),
        }
    }

    Poll::Ready(Ok(()))
}
