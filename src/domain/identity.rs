use super::fingerprint::Fingerprint;
use super::types::UserID;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub fingerprint: Fingerprint,
    pub user_id: UserID,
    pub label: Option<String>,
    pub public_key: String,
    pub created_at: i64,
}

impl Identity {
    pub fn new(
        fingerprint: Fingerprint,
        user_id: UserID,
        public_key: String,
        label: Option<String>,
    ) -> Self {
        Self {
            fingerprint,
            user_id,
            label,
            public_key,
            created_at: chrono::Utc::now().timestamp(),
        }
    }
}
