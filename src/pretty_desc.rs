use authenticator::{
    crypto::{COSEEC2Key, COSEKey, COSEKeyType},
    ctap2::{
        attestation::{
            AttestationStatement, AttestationStatementPacked, AttestedCredentialData,
            AuthenticatorData,
        },
        commands::credential_management::{
            CredentialList, CredentialListEntry, CredentialRpListEntry,
        },
        server::{CredentialProtectionPolicy, PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity, RelyingParty},
    },
    Assertion, AttestationObject, CredentialManagementResult, GetAssertionResult,
    MakeCredentialsResult,
};
use base64::Engine;

fn base64_encode<T: AsRef<[u8]>>(v: T) -> String {
    base64::engine::general_purpose::STANDARD.encode(v)
}

pub trait PrettyDesc {
    fn desc(&self) -> String;
}

impl<T: PrettyDescImpl> PrettyDesc for T {
    fn desc(&self) -> String {
        let lines = self.desc_lines();
        lines.join("\n")
    }
}

trait PrettyDescImpl {
    fn desc_lines(&self) -> Vec<String>;
    fn child_desc(&self) -> Vec<String> {
        self.desc_lines()
            .into_iter()
            .map(|x| "    ".to_string() + &x)
            .collect()
    }
}

impl<T: PrettyDescImpl> PrettyDescImpl for Option<T> {
    fn desc_lines(&self) -> Vec<String> {
        match self {
            Some(x) => x.desc_lines(),
            None => vec![],
        }
    }
}

impl PrettyDescImpl for AttestationStatementPacked {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["AttestationStatementPacked:".to_string()];
        lines.push(format!("    Algorithm: {:?}", self.alg));
        lines.push(format!("    Signature: {:?}", self.sig));
        if self.attestation_cert.len() > 0 {
            lines.push(format!(
                "    Certificate: {}",
                base64_encode(&self.attestation_cert[0])
            ));
        }
        lines
    }
}

impl PrettyDescImpl for AttestationStatement {
    fn desc_lines(&self) -> Vec<String> {
        match self {
            AttestationStatement::Packed(x) => x.desc_lines(),
            _ => vec![format!("{:?}", self)],
        }
    }
}

impl PrettyDescImpl for AttestationObject {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["AttestationObject:".to_string()];
        lines.extend(self.att_stmt.child_desc());
        lines.extend(self.auth_data.child_desc());
        lines
    }
}

impl PrettyDescImpl for COSEEC2Key {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["EC2 Key:".to_string()];
        lines.push(format!("    Curve: {:?}", self.curve));
        lines.push(format!("    X: {}", base64_encode(&self.x)));
        lines.push(format!("    Y: {}", base64_encode(&self.y)));
        lines
    }
}

impl PrettyDescImpl for COSEKeyType {
    fn desc_lines(&self) -> Vec<String> {
        match self {
            Self::EC2(x) => x.desc_lines(),
            _ => vec![format!("{:?}", self)],
        }
    }
}

impl PrettyDescImpl for COSEKey {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["COSEKey:".to_string()];
        lines.push(format!("    Alg: {:?}", self.alg));
        lines.extend(self.key.child_desc());
        lines
    }
}

impl PrettyDescImpl for AttestedCredentialData {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["AttestedCredentialData:".to_string()];
        lines.push(format!("    AAGUID: {:?}", self.aaguid));
        lines.push(format!(
            "    Credential ID: {}",
            base64_encode(&self.credential_id)
        ));
        lines.extend(self.credential_public_key.child_desc());
        lines
    }
}

impl PrettyDescImpl for AuthenticatorData {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["AuthenticatorData:".to_string()];
        lines.push(format!("    RP ID Hash: {:?}", self.rp_id_hash));
        lines.push(format!("    Flags: {:?}", self.flags));
        lines.push(format!("    Signature Counter: {}", self.counter));
        lines.extend(self.credential_data.child_desc());
        lines
    }
}

impl PrettyDescImpl for MakeCredentialsResult {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["MakeCredentialResult:".to_string()];
        lines.extend(self.att_obj.child_desc());
        lines.push(format!("    Attachment: {:?}", self.attachment));
        lines.push(format!("    Extensions: {:?}", self.extensions));
        lines
    }
}

impl PrettyDescImpl for PublicKeyCredentialUserEntity {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["User:".to_string()];
        lines.push(format!("    ID: \"{}\"", base64_encode(&self.id)));
        if let Some(name) = &self.name {
            lines.push(format!("    Name: \"{}\"", name));
        }
        if let Some(name) = &self.display_name {
            lines.push(format!("    Display Name: \"{}\"", name));
        }
        lines
    }
}

impl PrettyDescImpl for PublicKeyCredentialDescriptor {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["Public Key:".to_string()];
        lines.push(format!("    ID: {}", base64_encode(&self.id)));
        lines.push(format!("    Transports: {:?}", self.transports));
        lines
    }
}

impl PrettyDescImpl for Assertion {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["Assertion:".to_string()];
        lines.extend(self.credentials.child_desc());
        lines.extend(self.auth_data.child_desc());
        lines.push(format!("    Signature: {}", base64_encode(&self.signature)));
        lines.extend(self.user.child_desc());
        lines
    }
}

impl PrettyDescImpl for GetAssertionResult {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["GetAssertionResult:".to_string()];
        lines.extend(self.assertion.child_desc());
        lines.push(format!("    Attachment: {:?}", self.attachment));
        lines.push(format!("    Extensions: {:?}", self.extensions));
        lines
    }
}

impl PrettyDescImpl for RelyingParty {
    fn desc_lines(&self) -> Vec<String> {
        vec![format!(
            "RelyingParty - (ID: \"{}\", Name: \"{:?}\")",
            self.id, self.name
        )]
    }
}

fn credential_protection_policy(val: u64) -> Option<CredentialProtectionPolicy> {
    match val {
        1 => Some(CredentialProtectionPolicy::UserVerificationOptional),
        2 => Some(CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList),
        3 => Some(CredentialProtectionPolicy::UserVerificationRequired),
        _ => None,
    }
}

impl PrettyDescImpl for CredentialListEntry {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec![];
        lines.push(format!("Credential (ID: \"{}\"):", base64_encode(&self.credential_id.id)));
        // lines.push(format!("    User ID: \"{}\"", base64_encode(&self.user.id)));
        // if let Some(name) = &self.user.name {
        //     lines.push(format!("    User Name: \"{}\"", name));
        // }
        lines.extend(self.user.child_desc());
        if let Some(policy) = credential_protection_policy(self.cred_protect) {
            lines.push(format!(
                "    Credential Protection Policy: {:?}",
                policy
            ));
        }
        if let Some(key) = &self.large_blob_key {
            lines.push(format!("    Large Blob Key: {:?}", key));
        }
        lines
    }
}

impl PrettyDescImpl for CredentialRpListEntry {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec![];
        if let Some(name) = &self.rp.name {
            lines.push(format!("RelyingParty (\"{}\", \"{}\"):",self.rp.id, name));
        } else {
            lines.push(format!("RelyingParty (\"{}\"):",self.rp.id));
        }
        for cred in self.credentials.iter() {
            lines.extend(cred.child_desc());
        }
        lines
    }
}

impl PrettyDescImpl for CredentialList {
    fn desc_lines(&self) -> Vec<String> {
        let count = self.existing_resident_credentials_count;
        let max_count = count + self.max_possible_remaining_resident_credentials_count;
        let mut lines = vec![];
        lines.push(format!(
            "Credential Count: {} (Maximum: {})",
            count, max_count
        ));
        for credential in self.credential_list.iter() {
            lines.extend(credential.desc_lines());
        }
        lines
    }
}

impl PrettyDescImpl for CredentialManagementResult {
    fn desc_lines(&self) -> Vec<String> {
        match self {
            CredentialManagementResult::CredentialList(list) => list.desc_lines(),
            x => vec![format!("{:?}", x)],
        }
    }
}
