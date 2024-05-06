use authenticator::{
    crypto::{COSEEC2Key, COSEKey, COSEKeyType},
    ctap2::attestation::{
        AttestationStatement, AttestationStatementPacked, AttestedCredentialData, AuthenticatorData,
    },
    AttestationObject, MakeCredentialsResult,
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
            None => vec!["None".to_string()],
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
        lines.push(format!("    {:?}", self.attachment));
        lines.push(format!("    {:?}", self.extensions));
        lines
    }
}
