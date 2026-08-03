//! Error handling and core data types.
//!
//! This module provides the foundation for error management and the primary
//! data structures used throughout the age-credentials crate.
//!
//! # Submodules
//! - [`error`]: Defines the comprehensive [`AgeCredentialsError`] enum and the
//!   [`Result`] type alias used by all fallible operations.
//! - [`types`]: Contains the fundamental types for identities, metadata,
//!   fingerprints, user IDs, and key generation data.
//!
//! # Re‑exports
//! For convenience, all public items from both submodules are re‑exported at
//! this module level. This means you can import everything you need directly
//! from `age_credentials::handler` without needing to reference the submodules
//! individually.

pub mod error;
pub mod types;

pub use error::*;
pub use types::*;
