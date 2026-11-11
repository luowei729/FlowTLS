//! QUIC 内核封装。
//!
//! 只使用 quinn-proto 的传输状态机，socket 由 faketcp 层提供。

pub mod capped;
pub mod config;
