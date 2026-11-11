//! FakeTCP 层：手工构造 TCP 外观的报文，内部承载 QUIC 数据报。
//!
//! 模块划分：
//! - packet：IP/TCP 头构造与解析、校验和
//! - socket：AF_PACKET 收包 / IPPROTO_RAW 发包
//! - codec：伪 TLS 记录 + 外层 AEAD

pub mod codec;
pub mod packet;
pub mod socket;
