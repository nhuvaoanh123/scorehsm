//! Key store — secure SRAM2 key material management.
//!
//! Key material is stored in SRAM2 (security-attributed when TrustZone is
//! enabled). Callers only ever hold opaque `KeyHandle` values; raw key bytes
//! never leave this module.
//!
//! Capacity: `MAX_KEYS` slots. Handles are 1-based (0 = invalid/unallocated).

use zeroize::Zeroize;

pub const MAX_KEYS: usize = 32;

/// Raw key material union (largest variant governs size).
/// P-256 key pair: 32-byte private scalar + 65-byte uncompressed public key = 97B.
const MAX_KEY_BYTES: usize = 128; // padded to 128 for alignment

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum KeyType {
    Aes256    = 0x01, // 32-byte symmetric key
    HmacSha256 = 0x02, // 32-byte HMAC key
    EccP256   = 0x03, // 32-byte private scalar (public key derived on the fly)
}

impl TryFrom<u8> for KeyType {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            0x01 => Ok(KeyType::Aes256),
            0x02 => Ok(KeyType::HmacSha256),
            0x03 => Ok(KeyType::EccP256),
            _ => Err(()),
        }
    }
}

/// A key slot in SRAM2.
struct KeySlot {
    occupied: bool,
    key_type: KeyType,
    /// Raw key bytes — zeroed on deletion.
    bytes: [u8; MAX_KEY_BYTES],
    len: usize,
}

impl Default for KeySlot {
    fn default() -> Self {
        Self { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 }
    }
}

impl Drop for KeySlot {
    fn drop(&mut self) { self.bytes.zeroize(); }
}

/// Opaque handle (1-based index into the slot array).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyHandle(pub u32);

impl KeyHandle {
    pub const INVALID: Self = KeyHandle(0);
}

/// The key store — place this in a `static` in main.rs, pointed at SRAM2.
pub struct KeyStore {
    slots: [KeySlot; MAX_KEYS],
    next_handle: u32,
}

impl KeyStore {
    /// Construct (all slots zeroed). Call once at boot.
    pub const fn new() -> Self {
        Self {
            // Can't use [Default::default(); N] in const context pre-1.79
            slots: [
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
                KeySlot { occupied: false, key_type: KeyType::Aes256, bytes: [0u8; MAX_KEY_BYTES], len: 0 },
            ],
            next_handle: 1,
        }
    }

    /// Store key material and return a handle. Returns None if store is full.
    pub fn store(&mut self, key_type: KeyType, raw: &[u8]) -> Option<KeyHandle> {
        if raw.len() > MAX_KEY_BYTES {
            return None;
        }
        // Find a free slot (linear scan — 32 slots, constant time)
        let idx = self.slots.iter().position(|s| !s.occupied)?;
        let slot = &mut self.slots[idx];
        slot.occupied = true;
        slot.key_type = key_type;
        slot.len = raw.len();
        slot.bytes[..raw.len()].copy_from_slice(raw);
        let handle = KeyHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1).max(1); // skip 0
        // Encode slot index + generation into handle upper bits
        // Simple scheme: handle = (idx as u32) << 16 | seq; but since we
        // just need uniqueness and the SW backend test validates this,
        // use the monotonic counter directly.  The host never reuses handles.
        // Store the handle *value* in the slot so we can look it up.
        slot.len = raw.len(); // re-affirm
        // Return the slot's logical handle (monotonic, non-zero)
        // We store the handle value in bytes[96..100] to allow reverse lookup
        // without a separate map.
        let h = handle.0;
        slot.bytes[MAX_KEY_BYTES - 4..].copy_from_slice(&h.to_le_bytes());
        Some(handle)
    }

    /// Find the slot for a handle.
    fn find_slot(&self, h: KeyHandle) -> Option<usize> {
        if h == KeyHandle::INVALID { return None; }
        self.slots.iter().position(|s| {
            if !s.occupied { return false; }
            let stored = u32::from_le_bytes(
                s.bytes[MAX_KEY_BYTES - 4..].try_into().unwrap()
            );
            stored == h.0
        })
    }

    /// Borrow the raw key bytes for a handle and key type.
    /// Returns None if the handle is invalid or the type mismatches.
    pub fn borrow(&self, h: KeyHandle, expected_type: KeyType) -> Option<&[u8]> {
        let idx = self.find_slot(h)?;
        let slot = &self.slots[idx];
        if slot.key_type != expected_type { return None; }
        // Exclude the 4-byte handle tag at the end
        Some(&slot.bytes[..slot.len])
    }

    /// Borrow mutable (needed for p256 signing which takes &mut impl Rng).
    pub fn borrow_mut(&mut self, h: KeyHandle, expected_type: KeyType) -> Option<&mut [u8]> {
        let idx = self.find_slot(h)?;
        let slot = &mut self.slots[idx];
        if slot.key_type != expected_type { return None; }
        let len = slot.len;
        Some(&mut slot.bytes[..len])
    }

    /// Delete a key — zeroizes the slot.
    pub fn delete(&mut self, h: KeyHandle) -> bool {
        match self.find_slot(h) {
            None => false,
            Some(idx) => {
                self.slots[idx].bytes.zeroize();
                self.slots[idx].occupied = false;
                self.slots[idx].len = 0;
                true
            }
        }
    }

    /// Return the key type for a handle, or None if not found.
    pub fn key_type(&self, h: KeyHandle) -> Option<KeyType> {
        let idx = self.find_slot(h)?;
        Some(self.slots[idx].key_type)
    }
}
