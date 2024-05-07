use authenticator::{
    crypto::{COSEEC2Key, COSEKey, COSEKeyType}, ctap2::{attestation::{
        AttestationStatement, AttestationStatementPacked, AttestedCredentialData, AuthenticatorData,
    }, commands::credential_management::{CredentialList, CredentialListEntry, CredentialRpListEntry}, server::{PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity, RelyingParty}}, Assertion, AttestationObject, CredentialManagementResult, GetAssertionResult, MakeCredentialsResult
};
use base64::Engine;

fn base64_encode<T: AsRef<[u8]>>(v: T) -> String {
    base64::engine::general_purpose::STANDARD.encode(v)
}

pub trait PrettyDesc {
    fn desc(&self) -> String {
        let lines = self.desc_lines();
        lines.join("\n")
    }
    fn desc_lines(&self) -> Vec<String>;
    fn child_desc(&self) -> Vec<String> {
        self.desc_lines()
            .into_iter()
            .map(|x| "    ".to_string() + &x)
            .collect()
    }
}

impl<T: PrettyDesc> PrettyDesc for Option<T> {
    fn desc_lines(&self) -> Vec<String> {
        match self {
            Some(x) => x.desc_lines(),
            None => vec![],
        }
    }
}

impl PrettyDesc for AttestationStatementPacked {
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

impl PrettyDesc for AttestationStatement {
    fn desc_lines(&self) -> Vec<String> {
        match self {
            AttestationStatement::Packed(x) => x.desc_lines(),
            _ => vec![format!("{:?}", self)],
        }
    }
}

impl PrettyDesc for AttestationObject {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["AttestationObject:".to_string()];
        lines.extend(self.att_stmt.child_desc());
        lines.extend(self.auth_data.child_desc());
        lines
    }
}

impl PrettyDesc for COSEEC2Key {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["EC2 Key:".to_string()];
        lines.push(format!("    Curve: {:?}", self.curve));
        lines.push(format!("    X: {}", base64_encode(&self.x)));
        lines.push(format!("    Y: {}", base64_encode(&self.y)));
        lines
    }
}

impl PrettyDesc for COSEKeyType {
    fn desc_lines(&self) -> Vec<String> {
        match self {
            Self::EC2(x) => x.desc_lines(),
            _ => vec![format!("{:?}", self)],
        }
    }
}

impl PrettyDesc for COSEKey {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["COSEKey:".to_string()];
        lines.push(format!("    Alg: {:?}", self.alg));
        lines.extend(self.key.child_desc());
        lines
    }
}

impl PrettyDesc for AttestedCredentialData {
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

impl PrettyDesc for AuthenticatorData {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["AuthenticatorData:".to_string()];
        lines.push(format!("    RP ID Hash: {:?}", self.rp_id_hash));
        lines.push(format!("    Flags: {:?}", self.flags));
        lines.push(format!("    Signature Counter: {}", self.counter));
        lines.extend(self.credential_data.child_desc());
        lines
    }
}

impl PrettyDesc for MakeCredentialsResult {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["MakeCredentialResult:".to_string()];
        lines.extend(self.att_obj.child_desc());
        lines.push(format!("    Attachment: {:?}", self.attachment));
        lines.push(format!("    Extensions: {:?}", self.extensions));
        lines
    }
}

impl PrettyDesc for PublicKeyCredentialUserEntity {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["User:".to_string()];
        lines.push(format!("    ID: {}", base64_encode(&self.id)));
        lines.push(format!("    Name: {:?}", self.name));
        lines.push(format!("    Display Name: {:?}", self.display_name));
        lines
    }
}

impl PrettyDesc for PublicKeyCredentialDescriptor {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["Public Key:".to_string()];
        lines.push(format!("    ID: {}", base64_encode(&self.id)));
        lines.push(format!("    Transports: {:?}", self.transports));
        lines
    }
}

impl PrettyDesc for Assertion {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["Assertion:".to_string()];
        lines.extend(self.credentials.child_desc());
        lines.extend(self.auth_data.child_desc());
        lines.push(format!("    Signature: {}", base64_encode(&self.signature)));
        lines.extend(self.user.child_desc());
        lines
    }
}

impl PrettyDesc for GetAssertionResult {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["GetAssertionResult:".to_string()];
        lines.extend(self.assertion.child_desc());
        lines.push(format!("    Attachment: {:?}", self.attachment));
        lines.push(format!("    Extensions: {:?}", self.extensions));
        lines
    }
}

impl PrettyDesc for RelyingParty {
    fn desc_lines(&self) -> Vec<String> {
        vec![format!("RelyingParty - (ID: \"{}\", Name: \"{:?}\")", self.id, self.name)]
    }
}

impl PrettyDesc for CredentialListEntry {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["Credential:".to_string()];
        lines.extend(self.user.child_desc());
        lines.extend(self.credential_id.child_desc());
        lines.extend(self.public_key.child_desc());
        lines.push(format!("    Credential Protection Policy: {}", self.cred_protect));
        lines.push(format!("    Large Blob Key: {:?}", self.large_blob_key));
        lines
    }
}

impl PrettyDesc for CredentialRpListEntry {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["RPEntry:".to_string()];
        lines.extend(self.rp.child_desc());
        lines.push(format!("    RP ID Hash: {}", base64_encode(&self.rp_id_hash)));
        for cred in self.credentials.iter() {
            lines.extend(cred.child_desc());
        }
        lines
    }
}

impl PrettyDesc for CredentialList {
    fn desc_lines(&self) -> Vec<String> {
        let mut lines = vec!["CredentialList:".to_string()];
        lines.push(format!("    Count: {}", self.existing_resident_credentials_count));
        lines.push(format!("    Max possible remaining credentials: {}", self.max_possible_remaining_resident_credentials_count));
        for credential in self.credential_list.iter() {
            lines.extend(credential.child_desc());
        }
        lines
    }
}

impl PrettyDesc for CredentialManagementResult {
    fn desc_lines(&self) -> Vec<String> {
        match self {
            CredentialManagementResult::CredentialList(list) => list.desc_lines(),
            x => vec![format!("{:?}", x)],
        }
    }
}
