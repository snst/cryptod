//! Context store for managing streaming crypto contexts.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crypto_api::{HashContext, MacContext, CipherContext};

/// Unique handle for a streaming context.
pub type ContextHandle = u64;

/// Enum wrapping different context types.
pub enum StreamingContextType {
    Hash(Box<dyn HashContext>),
    Mac(Box<dyn MacContext>),
    Cipher(Box<dyn CipherContext>),
}

/// Store for active streaming contexts in a session.
pub struct ContextStore {
    contexts: HashMap<ContextHandle, StreamingContextType>,
    next_handle: AtomicU64,
}

impl ContextStore {
    /// Create a new empty context store.
    pub fn new() -> Self {
        Self {
            contexts: HashMap::new(),
            next_handle: AtomicU64::new(1),
        }
    }

    /// Generate a new unique context handle.
    fn next_handle(&self) -> ContextHandle {
        self.next_handle.fetch_add(1, Ordering::SeqCst)
    }

    /// Insert a hash context and return its handle.
    pub fn insert_hash(&mut self, ctx: Box<dyn HashContext>) -> ContextHandle {
        let handle = self.next_handle();
        self.contexts.insert(handle, StreamingContextType::Hash(ctx));
        handle
    }

    /// Insert a MAC context and return its handle.
    pub fn insert_mac(&mut self, ctx: Box<dyn MacContext>) -> ContextHandle {
        let handle = self.next_handle();
        self.contexts.insert(handle, StreamingContextType::Mac(ctx));
        handle
    }

    /// Insert a cipher context and return its handle.
    pub fn insert_cipher(&mut self, ctx: Box<dyn CipherContext>) -> ContextHandle {
        let handle = self.next_handle();
        self.contexts.insert(handle, StreamingContextType::Cipher(ctx));
        handle
    }

    /// Get a mutable reference to a hash context.
    pub fn get_hash_mut(&mut self, handle: ContextHandle) -> Option<&mut Box<dyn HashContext>> {
        match self.contexts.get_mut(&handle)? {
            StreamingContextType::Hash(ctx) => Some(ctx),
            _ => None,
        }
    }

    /// Get a mutable reference to a MAC context.
    pub fn get_mac_mut(&mut self, handle: ContextHandle) -> Option<&mut Box<dyn MacContext>> {
        match self.contexts.get_mut(&handle)? {
            StreamingContextType::Mac(ctx) => Some(ctx),
            _ => None,
        }
    }

    /// Get a mutable reference to a cipher context.
    pub fn get_cipher_mut(&mut self, handle: ContextHandle) -> Option<&mut Box<dyn CipherContext>> {
        match self.contexts.get_mut(&handle)? {
            StreamingContextType::Cipher(ctx) => Some(ctx),
            _ => None,
        }
    }

    /// Remove and return a hash context.
    pub fn remove_hash(&mut self, handle: ContextHandle) -> Option<Box<dyn HashContext>> {
        match self.contexts.remove(&handle)? {
            StreamingContextType::Hash(ctx) => Some(ctx),
            other => {
                // Put it back if wrong type
                self.contexts.insert(handle, other);
                None
            }
        }
    }

    /// Remove and return a MAC context.
    pub fn remove_mac(&mut self, handle: ContextHandle) -> Option<Box<dyn MacContext>> {
        match self.contexts.remove(&handle)? {
            StreamingContextType::Mac(ctx) => Some(ctx),
            other => {
                self.contexts.insert(handle, other);
                None
            }
        }
    }

    /// Remove and return a cipher context.
    pub fn remove_cipher(&mut self, handle: ContextHandle) -> Option<Box<dyn CipherContext>> {
        match self.contexts.remove(&handle)? {
            StreamingContextType::Cipher(ctx) => Some(ctx),
            other => {
                self.contexts.insert(handle, other);
                None
            }
        }
    }

    /// Remove a context of any type (for cleanup/destroy).
    pub fn remove(&mut self, handle: ContextHandle) -> bool {
        self.contexts.remove(&handle).is_some()
    }

    // /// Get the number of active contexts.
    // pub fn len(&self) -> usize {
    //     self.contexts.len()
    // }

    // /// Check if the store is empty.
    // pub fn is_empty(&self) -> bool {
    //     self.contexts.is_empty()
    // }
}

impl Default for ContextStore {
    fn default() -> Self {
        Self::new()
    }
}
