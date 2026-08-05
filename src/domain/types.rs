use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserID {
    pub name: String,
    pub email: String,
}

impl UserID {
    pub fn new(
        name: impl Into<String>,
        email: impl Into<String>,
    ) -> Result<Self, crate::domain::error::AccountError> {
        let name = name.into();
        let email = email.into();
        super::validation::validate_user_name(&name)?;
        super::validation::validate_user_email(&email)?;
        Ok(Self {
            name: name.trim().to_string(),
            email: email.trim().to_string(),
        })
    }

    pub fn to_formatted(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }
}

#[derive(Debug, Clone)]
pub struct KeyGenData {
    pub public_key: String,
    pub secret_key: Zeroizing<String>,
}
