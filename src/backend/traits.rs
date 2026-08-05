use crate::domain::error::Result;
use crate::domain::fingerprint::Fingerprint;
use crate::domain::identity::Identity;
use zeroize::Zeroizing;

pub trait AccountBackend {
    fn save_identity(&mut self, identity: &Identity) -> Result<()>;

    fn load_identity(&self, fingerprint: &Fingerprint) -> Result<Option<Identity>>;

    fn delete_identity(&mut self, fingerprint: &Fingerprint) -> Result<()>;

    fn store_encrypted_private_key(
        &mut self,
        fingerprint: &Fingerprint,
        encrypted_key: &[u8],
    ) -> Result<()>;

    fn load_encrypted_private_key(
        &self,
        fingerprint: &Fingerprint,
    ) -> Result<Option<Zeroizing<Vec<u8>>>>;

    fn list_fingerprints(&self) -> Result<Vec<Fingerprint>>;

    fn find_by_email(&self, email: &str) -> Result<Option<Fingerprint>> {
        for fp in self.list_fingerprints()? {
            if let Some(identity) = self.load_identity(&fp)?
                && identity.user_id.email == email
            {
                return Ok(Some(fp));
            }
        }
        Ok(None)
    }
}
