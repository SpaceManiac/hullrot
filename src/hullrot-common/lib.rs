/*
Hullrot is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hullrot is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with Hullrot.  If not, see <http://www.gnu.org/licenses/>.
*/

// ----------------------------------------------------------------------------
// Buffered I/O helpers

use std::io::{self, BufRead, Read, Write};

const DEFAULT_BUF_SIZE: usize = 8 * 1024;

/// Reimplementation of a `BufReader` which does not own its inner stream.
pub struct BufReader {
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
}

impl Default for BufReader {
    fn default() -> Self {
        BufReader::with_capacity(DEFAULT_BUF_SIZE)
    }
}

impl BufReader {
    pub fn new() -> BufReader {
        Default::default()
    }

    pub fn with_capacity(cap: usize) -> BufReader {
        BufReader {
            buf: vec![0; cap].into_boxed_slice(),
            pos: 0,
            cap: 0,
        }
    }

    pub fn with<'b, 'r, R: ?Sized>(&'b mut self, read: &'r mut R) -> BufReaderWith<'b, 'r, R> {
        BufReaderWith {
            buf: self,
            inner: read,
        }
    }
}

pub struct BufReaderWith<'b, 'r, R: ?Sized + 'r> {
    buf: &'b mut BufReader,
    inner: &'r mut R,
}

impl<'r, R: Read + ?Sized + 'r> Read for BufReaderWith<'_, 'r, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we don't have any buffered data and we're doing a massive read
        // (larger than our internal buffer), bypass our internal buffer
        // entirely.
        if self.buf.pos == self.buf.cap && buf.len() >= self.buf.buf.len() {
            return self.inner.read(buf);
        }
        let nread = {
            let mut rem = self.fill_buf()?;
            rem.read(buf)?
        };
        self.consume(nread);
        Ok(nread)
    }
}

impl<'r, R: Read + ?Sized + 'r> BufRead for BufReaderWith<'_, 'r, R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        // If we've reached the end of our internal buffer then we need to fetch
        // some more data from the underlying reader.
        // Branch using `>=` instead of the more correct `==`
        // to tell the compiler that the pos..cap slice is always valid.
        if self.buf.pos >= self.buf.cap {
            debug_assert!(self.buf.pos == self.buf.cap);
            self.buf.cap = self.inner.read(&mut self.buf.buf)?;
            self.buf.pos = 0;
        }
        Ok(&self.buf.buf[self.buf.pos..self.buf.cap])
    }

    fn consume(&mut self, amt: usize) {
        self.buf.pos = ::std::cmp::min(self.buf.pos + amt, self.buf.cap);
    }
}

/// Reimplementation of a `BufWriter` which does not own its inner stream,
/// and handles `WouldBlock` errors appropriately.
pub struct BufWriter {
    buf: Vec<u8>,
    cap: usize,
    writable: bool,
}

impl Default for BufWriter {
    fn default() -> Self {
        BufWriter::with_capacity(DEFAULT_BUF_SIZE)
    }
}

impl BufWriter {
    pub fn new() -> BufWriter {
        Default::default()
    }

    pub fn with_capacity(cap: usize) -> BufWriter {
        BufWriter {
            buf: Vec::with_capacity(cap),
            cap,
            writable: false,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline]
    pub fn mark_writable(&mut self) {
        self.writable = true;
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    pub fn with<'b, 'w, W: Write + ?Sized>(
        &'b mut self,
        write: &'w mut W,
    ) -> BufWriterWith<'b, 'w, W> {
        BufWriterWith {
            buf: self,
            inner: write,
        }
    }
}

pub struct BufWriterWith<'b, 'w, W: Write + ?Sized + 'w> {
    buf: &'b mut BufWriter,
    inner: &'w mut W,
}

impl<'w, W: Write + ?Sized + 'w> BufWriterWith<'_, 'w, W> {
    pub fn flush_buf(&mut self) -> io::Result<()> {
        let mut written = 0;
        let len = self.buf.buf.len();
        let mut ret = Ok(());
        if len == 0 {
            return ret;
        }
        //println!("flush_buf({})", len);
        while written < len {
            let r = self.inner.write(&self.buf.buf[written..]);
            //println!("write: {:?}", r);
            match r {
                Ok(0) => {
                    ret = Err(io::ErrorKind::WriteZero.into());
                    break;
                }
                Ok(n) => written += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.buf.writable = false;
                    break;
                }
                Err(e) => {
                    ret = Err(e);
                    break;
                }
            }
        }
        if written > 0 {
            self.buf.buf.drain(..written);
        }
        ret
    }
}

impl<'w, W: Write + ?Sized + 'w> Write for BufWriterWith<'_, 'w, W> {
    // If this succeeds, it will always succeed with the correct length. The
    // input will always be written either out or to the buffer. If a given
    // write would have returned `WouldBlock`, the `writable` flag is unset and
    // `Ok` is returned.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // If we would go over capacity, flush our buffer first.
        // Use `cap` rather than `buf.capacity()` because we allow `buf` to
        // grow beyond its initial capacity in order to store oversized writes.
        if self.buf.buf.len() + buf.len() > self.buf.cap {
            self.flush_buf()?;
        }
        // Our buffer will have been completely flushed if there's been no
        // `WouldBlock`. In that case, a big write gets written now.
        if buf.len() >= self.buf.buf.capacity() && self.buf.buf.is_empty() {
            match self.inner.write(buf) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    Write::write(&mut self.buf.buf, buf)
                }
                other => other,
            }
        } else {
            Write::write(&mut self.buf.buf, buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buf().and_then(|()| self.inner.flush())
    }
}
