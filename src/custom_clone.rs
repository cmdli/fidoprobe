use authenticator::ctap2::commands::credential_management::{
    CredentialList, CredentialListEntry, CredentialRpListEntry,
};

pub trait CustomClone {
    fn custom_clone(&self) -> Self;
}

impl<T: CustomClone> CustomClone for Vec<T> {
    fn custom_clone(&self) -> Self {
        let mut vec = vec![];
        for item in self.iter() {
            vec.push(item.custom_clone());
        }
        vec
    }
}

impl CustomClone for CredentialList {
    fn custom_clone(&self) -> Self {
        CredentialList {
            existing_resident_credentials_count: self.existing_resident_credentials_count,
            max_possible_remaining_resident_credentials_count: self
                .max_possible_remaining_resident_credentials_count,
            credential_list: self.credential_list.custom_clone(),
        }
    }
}

impl CustomClone for CredentialRpListEntry {
    fn custom_clone(&self) -> Self {
        CredentialRpListEntry {
            rp: self.rp.clone(),
            rp_id_hash: self.rp_id_hash.clone(),
            credentials: self.credentials.custom_clone(),
        }
    }
}

impl CustomClone for CredentialListEntry {
    fn custom_clone(&self) -> Self {
        CredentialListEntry {
            user: self.user.clone(),
            credential_id: self.credential_id.clone(),
            cred_protect: self.cred_protect,
            public_key: self.public_key.clone(),
            large_blob_key: self.large_blob_key.clone(),
        }
    }
}
