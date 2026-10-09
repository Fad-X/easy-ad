//! Credential handling: password, NTLM hash, and Kerberos authentication modes.

use serde::Serialize;

/// The secret half of a credential pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    /// Plaintext password.
    Password(String),
    /// NTLM hash, either `aad3b435b51404eeaad3b435b51404ee:31d6...` (LM:NT) or bare NT hash.
    NtlmHash(String),
}

impl Secret {
    /// The NT portion of the hash (second half of `LM:NT`, or the whole hash if bare).
    pub fn nt_part(&self) -> Option<String> {
        match self {
            Secret::NtlmHash(h) => {
                let parts: Vec<&str> = h.split(':').collect();
                if parts.len() == 2 {
                    Some(parts[1].to_string())
                } else {
                    Some(h.clone())
                }
            }
            Secret::Password(_) => None,
        }
    }

    /// Never print secrets in logs.
    pub fn redacted(&self) -> &'static str {
        match self {
            Secret::Password(_) => "***PASSWORD***",
            Secret::NtlmHash(_) => "***NTLM-HASH***",
        }
    }
}

/// A full credential: username + secret + auth mode.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub secret: Secret,
    /// Whether to prefer Kerberos authentication where the protocol supports it.
    pub kerberos: bool,
}

impl Credentials {
    pub fn with_password(username: impl Into<String>, password: impl Into<String>, kerberos: bool) -> Self {
        Credentials {
            username: username.into(),
            secret: Secret::Password(password.into()),
            kerberos,
        }
    }

    pub fn hash(username: impl Into<String>, hash: impl Into<String>) -> Self {
        Credentials {
            username: username.into(),
            secret: Secret::NtlmHash(hash.into()),
            kerberos: false,
        }
    }

    /// `DOMAIN\user` form used by NTLM-oriented protocols (SMB, WinRM, MSSQL).
    pub fn qualified(&self, domain: &str) -> String {
        if self.username.contains('\\') || self.username.contains('@') {
            self.username.clone()
        } else {
            format!("{}\\{}", domain, self.username)
        }
    }

    /// Plain password, if available.
    pub fn password(&self) -> Option<&str> {
        match &self.secret {
            Secret::Password(p) => Some(p),
            Secret::NtlmHash(_) => None,
        }
    }

    /// Username as a Kerberos principal component (strip `DOMAIN\` prefix).
    pub fn krb_user(&self) -> String {
        self.username
            .rsplit('\\')
            .next()
            .unwrap_or(&self.username)
            .split('@')
            .next()
            .unwrap_or(&self.username)
            .to_string()
    }
}

/// Serializable, redacted credential description for reports/auditing.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialRecord {
    pub username: String,
    pub auth_type: String,
    pub kerberos: bool,
}

impl From<&Credentials> for CredentialRecord {
    fn from(c: &Credentials) -> Self {
        CredentialRecord {
            username: c.username.clone(),
            auth_type: match c.secret {
                Secret::Password(_) => "password".to_string(),
                Secret::NtlmHash(_) => "ntlm_hash".to_string(),
            },
            kerberos: c.kerberos,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_lm_nt_hash() {
        let s = Secret::NtlmHash("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into());
        assert_eq!(
            s.nt_part().unwrap(),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
        let bare = Secret::NtlmHash("31d6cfe0d16ae931b73c59d7e0c089c0".into());
        assert_eq!(bare.nt_part().unwrap(), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn qualifies_username_with_domain() {
        let c = Credentials::with_password("admin", "x", false);
        assert_eq!(c.qualified("CORP"), "CORP\\admin");
        let c2 = Credentials::with_password("CORP\\admin", "x", false);
        assert_eq!(c2.qualified("CORP"), "CORP\\admin");
    }

    #[test]
    fn krb_user_strips_domain() {
        let c = Credentials::with_password("CORP\\svc_recon", "x", true);
        assert_eq!(c.krb_user(), "svc_recon");
        let c2 = Credentials::with_password("svc@CORP.LOCAL", "x", true);
        assert_eq!(c2.krb_user(), "svc");
    }
}
