//! Disposable-VM core pipe experiment. No production permit/key/identity implementation.
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const SOCKET: &[u8] = b"/run/asservat-crash/socket\0";
const MAX_BYTES: usize = 16 * 1024 * 1024;
fn wait(fd: i32, events: i16, end: Instant) -> io::Result<()> {
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() { return Err(io::ErrorKind::TimedOut.into()); }
        let mut p = libc::pollfd { fd, events, revents: 0 };
        let n = unsafe { libc::poll(&mut p, 1, left.as_millis().clamp(1, 2000) as i32) };
        if n > 0 { return Ok(()); }
        if n == 0 { return Err(io::ErrorKind::TimedOut.into()); }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted { return Err(e); }
    }
}
fn send(s: &mut UnixStream, mut b: &[u8], end: Instant) -> io::Result<()> {
    while !b.is_empty() {
        if Instant::now() >= end { return Err(io::ErrorKind::TimedOut.into()); }
        match s.write(b) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => b = &b[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => wait(s.as_raw_fd(), libc::POLLOUT, end)?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn receive(s: &mut UnixStream, end: Instant) -> io::Result<u8> {
    let mut b = [0u8];
    loop {
        wait(s.as_raw_fd(), libc::POLLIN, end)?;
        match s.read(&mut b) {
            Ok(1) => return Ok(b[0]),
            Ok(_) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
}
fn connect(end: Instant) -> io::Result<UnixStream> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    let s = unsafe { UnixStream::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    for (i, c) in SOCKET.iter().enumerate() { addr.sun_path[i] = *c as _; }
    let ret = unsafe { libc::connect(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&addr) as _) };
    if ret != 0 {
        let e = io::Error::last_os_error();
        // EAGAIN for an exhausted Unix listen queue refuses promptly; never blocking connect.
        if e.raw_os_error() != Some(libc::EINPROGRESS) { return Err(e); }
        wait(fd, libc::POLLOUT, end)?;
        let mut err = 0i32; let mut len = std::mem::size_of_val(&err) as libc::socklen_t;
        if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut _ as *mut _, &mut len) } != 0 { return Err(io::Error::last_os_error()); }
        if err != 0 { return Err(io::Error::from_raw_os_error(err)); }
    }
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut n = std::mem::size_of_val(&peer) as libc::socklen_t;
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut peer as *mut _ as *mut _, &mut n) } != 0 { return Err(io::Error::last_os_error()); }
    if peer.uid != 0 || peer.pid <= 0 { return Err(io::ErrorKind::PermissionDenied.into()); }
    Ok(s)
}
fn run() -> io::Result<()> {
    if !std::path::Path::new("/root/ASSERVAT_DISPOSABLE_VM").exists() { return Err(io::ErrorKind::PermissionDenied.into()); }
    let end = Instant::now() + Duration::from_secs(2);
    unsafe { libc::alarm(3); libc::prctl(libc::PR_SET_DUMPABLE, 0); }
    std::fs::write("/sys/fs/cgroup/asservat-helper/cgroup.procs", std::process::id().to_string())?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 { return Err(io::ErrorKind::InvalidInput.into()); }
    let mut ids = [0u32; 3];
    for (i, s) in args.iter().enumerate() { ids[i] = s.parse().map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?; }
    if ids[0] == 0 || ids[1] == 0 || ids[1] > 64 { return Err(io::ErrorKind::InvalidInput.into()); }
    let mut stat = String::new();
    File::open(format!("/proc/{}/stat", ids[0]))?.take(8193).read_to_string(&mut stat)?;
    if stat.len() > 8192 { return Err(io::ErrorKind::InvalidData.into()); }
    let (_, tail) = stat.rsplit_once(')').ok_or(io::ErrorKind::InvalidData)?;
    let start: u64 = tail.split_whitespace().nth(19).ok_or(io::ErrorKind::InvalidData)?.parse().map_err(|_| io::ErrorKind::InvalidData)?;
    let mut s = connect(end)?;
    send(&mut s, format!("{} {} {} {}\n", ids[0], start, ids[1], ids[2]).as_bytes(), end)?;
    if receive(&mut s, end)? != 1 { return Err(io::ErrorKind::PermissionDenied.into()); }
    let flags = unsafe { libc::fcntl(0, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 { return Err(io::Error::last_os_error()); }
    let mut input = unsafe { File::from_raw_fd(0) };
    let mut buf = [0u8; 65536]; let mut total = 0usize;
    loop {
        wait(0, libc::POLLIN, end)?;
        match input.read(&mut buf) {
            Ok(0) => { send(&mut s, &0u32.to_be_bytes(), end)?; if receive(&mut s, end)? != 2 { return Err(io::ErrorKind::InvalidData.into()); } return Ok(()); }
            Ok(n) => {
                if n > MAX_BYTES - total { return Err(io::ErrorKind::FileTooLarge.into()); }
                send(&mut s, &(n as u32).to_be_bytes(), end)?;
                send(&mut s, &buf[..n], end)?; total += n;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
}
fn main() { if run().is_err() { std::process::exit(1); } }
