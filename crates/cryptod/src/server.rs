//! Unix domain socket server using SOCK_SEQPACKET.

use std::path::Path;
use std::sync::Arc;
//use std::os::unix::net::UnixListener;
use std::io;
use tracing::{info, warn, error};

use crypto_native::NativeProvider;
use crate::session::Session;

/// Run the daemon server.
pub async fn run(socket_path: &Path) -> io::Result<()> {
    // Remove existing socket file if present
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    // Create parent directory if needed
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Create SOCK_SEQPACKET listener
    // Note: std::os::unix::net doesn't support SEQPACKET directly,
    // so we use raw socket creation
    let listener = create_seqpacket_listener(socket_path)?;

    // Create a single shared provider for all sessions
    let provider = Arc::new(NativeProvider::new());

    info!("Listening on {}", socket_path.display());

    // Accept loop
    loop {
        match accept_client(&listener) {
            Ok(stream) => {
                info!("New client connected");
                
                // Clone the Arc for this session
                let provider = Arc::clone(&provider);
                
                // Spawn a task to handle this client
                tokio::task::spawn_blocking(move || {
                    let mut session = Session::new(stream, provider);
                    if let Err(e) = session.run() {
                        warn!("Session error: {}", e);
                    }
                    info!("Client disconnected");
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

/// Create a SOCK_SEQPACKET Unix domain socket listener.
fn create_seqpacket_listener(path: &Path) -> io::Result<i32> {
    use std::os::unix::ffi::OsStrExt;
    
    // Create socket
    let fd = unsafe {
        libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0)
    };
    
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Build sockaddr_un
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    
    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Socket path too long"));
    }
    
    for (i, &byte) in path_bytes.iter().enumerate() {
        addr.sun_path[i] = byte as libc::c_char;
    }

    // Bind
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    // Listen
    let ret = unsafe { libc::listen(fd, 128) };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}

/// Accept a client connection from the SEQPACKET listener.
fn accept_client(listener_fd: &i32) -> io::Result<i32> {
    let fd = unsafe {
        libc::accept(*listener_fd, std::ptr::null_mut(), std::ptr::null_mut())
    };
    
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    
    Ok(fd)
}
