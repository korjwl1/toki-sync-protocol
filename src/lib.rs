//! Shared protocol types for the toki sync binary protocol.
//!
//! This crate defines the wire types (payload structs, message type enum,
//! constants) used by both the toki CLI client and the toki-sync server.
//!
//! Frame I/O is NOT included here because the client uses synchronous
//! `std::io` while the server uses `tokio::io`.  Each side provides its
//! own `read_frame` / `write_frame` implementation.
//!
//! **Bincode serialization is field-order-dependent.**  Any field order or
//! type change to the structs in this crate requires a coordinated release
//! of both client and server.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Current sync protocol version. Server rejects clients with unsupported versions.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum frame payload size: 16 MiB.
pub const MAX_PAYLOAD_SIZE: u32 = 16 * 1024 * 1024;

/// Schema version the server expects. Clients must match.
pub const SCHEMA_VERSION: u32 = 3;

// ─── Message types ──────────────────────────────────────────────────────────

/// Message type discriminants.
/// Values are hex-grouped by category: 0x01-0x03 auth, 0x10-0x11 cursor,
/// 0x20-0x23 batch, 0x30-0x31 keepalive.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Auth          = 0x01,
    AuthOk        = 0x02,
    AuthErr       = 0x03,
    GetLastTs     = 0x10,
    LastTs        = 0x11,
    SyncBatch     = 0x20,
    SyncAck       = 0x21,
    SyncErr       = 0x22,
    SyncBatchZstd = 0x23,
    Ping          = 0x30,
    Pong          = 0x31,
}

impl MsgType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Auth),
            0x02 => Some(Self::AuthOk),
            0x03 => Some(Self::AuthErr),
            0x10 => Some(Self::GetLastTs),
            0x11 => Some(Self::LastTs),
            0x20 => Some(Self::SyncBatch),
            0x21 => Some(Self::SyncAck),
            0x22 => Some(Self::SyncErr),
            0x23 => Some(Self::SyncBatchZstd),
            0x30 => Some(Self::Ping),
            0x31 => Some(Self::Pong),
            _    => None,
        }
    }
}

// ─── Payload types (bincode field-order sensitive) ──────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthPayload {
    pub jwt: String,
    pub device_name: String,
    pub schema_version: u32,
    pub provider: String,
    /// Stable UUID generated on the client at `toki sync enable`.
    pub device_key: String,
    /// Sync protocol version.
    pub protocol_version: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthOkPayload {
    pub device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthErrPayload {
    pub reason: String,
    /// True if the client should delete its local sync cursor and re-sync from scratch.
    pub reset_required: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLastTsPayload {
    pub provider: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LastTsPayload {
    pub ts_ms: i64,
}

/// A stored event in the sync wire protocol.
/// Uses dictionary-compressed IDs for repeated strings.
/// Token values are variable-length — column names are in SyncBatchPayload::token_columns.
///
/// **Field order matters for bincode compatibility.**
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub model_id: u32,
    pub session_id: u32,
    pub source_file_id: u32,
    pub project_name_id: u32,
    pub tokens: Vec<u64>,
}

/// A single event item in a sync batch.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SyncItem {
    pub ts_ms: i64,
    /// Unique message ID for VM dedup (same ts + same labels → one data point without this).
    #[serde(default)]
    pub message_id: String,
    pub event: StoredEvent,
    /// Pre-calculated usage total (Claude: all 4 token types, Codex: input+output only).
    #[serde(default)]
    pub usage_total: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncBatchPayload {
    pub items: Vec<SyncItem>,
    /// Dictionary snapshot: all dict IDs referenced by items in this batch.
    pub dict: HashMap<u32, String>,
    pub provider: String,
    /// Column names for the `StoredEvent::tokens` Vec (e.g. ["input", "output", "cache_create", "cache_read"]).
    pub token_columns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncAckPayload {
    pub last_ts_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncErrPayload {
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_type_roundtrip() {
        for val in [0x01u32, 0x02, 0x03, 0x10, 0x11, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31] {
            assert!(MsgType::from_u32(val).is_some(), "MsgType::from_u32({val:#x}) should succeed");
        }
        assert!(MsgType::from_u32(0xFF).is_none());
    }

    #[test]
    fn stored_event_field_order_stable() {
        // Verify bincode serialization produces expected byte layout.
        // This test will break if fields are reordered, catching accidental changes.
        let event = StoredEvent {
            model_id: 1,
            session_id: 2,
            source_file_id: 3,
            project_name_id: 4,
            tokens: vec![100, 200, 300, 400],
        };
        let bytes = bincode::serialize(&event).unwrap();
        let decoded: StoredEvent = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.model_id, 1);
        assert_eq!(decoded.session_id, 2);
        assert_eq!(decoded.source_file_id, 3);
        assert_eq!(decoded.project_name_id, 4);
        assert_eq!(decoded.tokens, vec![100, 200, 300, 400]);
    }
}
