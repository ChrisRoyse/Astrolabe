use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// A TCP adapter that enforces one monotonic deadline across every partial I/O
/// operation. OS socket timeouts alone are inactivity timers and restart after
/// each successful read/write, so they cannot bound a trickle-fed request.
pub(super) struct DeadlineStream<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}

impl<'a> DeadlineStream<'a> {
    pub(super) fn new(stream: &'a mut TcpStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }

    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "resident operation exceeded its monotonic deadline",
            ));
        }
        Ok(remaining)
    }
}

pub(super) fn read_bounded_line(
    reader: &mut impl BufRead,
    max_bytes: usize,
    context: &str,
) -> io::Result<Vec<u8>> {
    let limit = max_bytes.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{context} byte limit exceeds addressable memory"),
        )
    })?;
    let mut line = Vec::new();
    reader.take(limit as u64).read_until(b'\n', &mut line)?;
    if line.len() > max_bytes || !line.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{context} must be newline-terminated within {max_bytes} bytes"),
        ));
    }
    Ok(line)
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        let read = self.stream.read(buffer)?;
        self.remaining()?;
        Ok(read)
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        let written = self.stream.write(buffer)?;
        self.remaining()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()?;
        self.remaining().map(|_| ())
    }
}

pub(super) fn deadline_after(duration: Duration) -> io::Result<Instant> {
    Instant::now().checked_add(duration).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "resident deadline duration exceeds monotonic clock capacity",
        )
    })
}

pub(super) fn ensure_before(deadline: Instant, context: &str) -> io::Result<()> {
    if deadline.saturating_duration_since(Instant::now()).is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{context} exceeded its monotonic deadline"),
        ));
    }
    Ok(())
}

pub(super) fn connect_before(
    address: &std::net::SocketAddr,
    deadline: Instant,
) -> io::Result<TcpStream> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "resident connection deadline expired before connect",
        ));
    }
    let stream = TcpStream::connect_timeout(address, remaining)?;
    if deadline.saturating_duration_since(Instant::now()).is_zero() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "resident connection completed after its monotonic deadline",
        ));
    }
    Ok(stream)
}
