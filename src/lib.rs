//! let user_id = UserID::new("Alice Example", "alice@example.com")?;
pub mod config;
pub mod core;
pub mod handler;

pub use config::*;
pub use core::*;
pub use handler::*;
