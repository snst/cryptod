//! Client session handling.

use std::io::{self, 
    //Read, Write
    };
use std::sync::Arc;
use tracing::{
    //debug, 
    trace};

use crypto_native::NativeProvider;
//use crypto_api::CryptoProvider;

use crate::handler::Handler;
use crate::context_store::ContextStore;

/// Maximum message size (64 KB should be plenty for crypto operations)
const MAX_MESSAGE_SIZE: usize = 65536;

/// A client session managing a single connection.
pub struct Session {
    fd: i32,
    handler: Handler,
    recv_buf: Vec<u8>,
}

impl Session {
    /// Create a new session for the given socket file descriptor and shared provider.
    pub fn new(fd: i32, provider: Arc<NativeProvider>) -> Self {
        let context_store = ContextStore::new();
        
        Self {
            fd,
            handler: Handler::new(provider, context_store),
            recv_buf: vec![0u8; MAX_MESSAGE_SIZE],
        }
    }

    /// Run the session, processing messages until the client disconnects.
    pub fn run(&mut self) -> io::Result<()> {
        loop {
            // Receive a message (SEQPACKET preserves message boundaries)
            let n = self.recv_message()?;
            
            if n == 0 {
                // Client disconnected
                return Ok(());
            }

            let request_data = &self.recv_buf[..n];
            trace!("Received {} bytes", n);

            // Process the request
            let response_data = self.handler.handle_request(request_data);

            // Send response
            self.send_message(&response_data)?;
            trace!("Sent {} bytes", response_data.len());
        }
    }

    /// Receive a single message from the socket.
    fn recv_message(&mut self) -> io::Result<usize> {
        let n = unsafe {
            libc::recv(
                self.fd,
                self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                self.recv_buf.len(),
                0,
            )
        };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(n as usize)
    }

    /// Send a message to the socket.
    fn send_message(&self, data: &[u8]) -> io::Result<()> {
        let n = unsafe {
            libc::send(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
            )
        };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        if n as usize != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Failed to send complete message",
            ));
        }

        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
