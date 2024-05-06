mod pretty_desc;

use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs},
    crypto::{COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType},
    ctap2::{
        attestation::{
            AttestationCertificate, AttestationStatement, AttestationStatementPacked,
            AttestedCredentialData, AuthenticatorData,
        },
        server::{
            AuthenticationExtensionsClientInputs, PublicKeyCredentialParameters,
            PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement,
            UserVerificationRequirement,
        },
    },
    statecallback::StateCallback,
    AttestationObject, MakeCredentialsResult, StatusUpdate,
};
use pretty_desc::PrettyDesc;
use rand::{thread_rng, RngCore};
use std::{
    fmt::format,
    sync::mpsc::{channel, RecvError},
    thread,
};

/*
Usages:
    - Create a credential
    - List credentials on device for an origin
    - Get assertion of credential (possibly for a specified challenge)

Requirements:
    - Pretty print all results
*/

fn main() {
    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();

    let mut chall_bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut chall_bytes);

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(..)) => {
                panic!("STATUS: This can't happen when doing non-interactive usage");
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                println!("STATUS: Please select a device by touching one of them.");
            }
            Ok(StatusUpdate::PresenceRequired) => {
                println!("STATUS: waiting for user presence");
            }
            Ok(StatusUpdate::PinUvError(e)) => {
                panic!("Unexpected error: {:?}", e)
            }
            Ok(StatusUpdate::SelectResultNotice(_, _)) => {
                panic!("Unexpected select device notice")
            }
            Err(RecvError) => {
                println!("STATUS: end");
                return;
            }
        }
    });

    let user = PublicKeyCredentialUserEntity {
        id: "user_id".as_bytes().to_vec(),
        name: Some("A. User".to_string()),
        display_name: None,
    };
    let relying_party = RelyingParty {
        id: "Yo".to_string(),
        name: None,
    };
    let ctap_args = RegisterArgs {
        client_data_hash: chall_bytes,
        relying_party,
        origin: format!("https://example.com"),
        user,
        pub_cred_params: vec![
            PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
            },
            PublicKeyCredentialParameters {
                alg: COSEAlgorithm::RS256,
            },
        ],
        exclude_list: vec![],
        user_verification_req: UserVerificationRequirement::Preferred,
        resident_key_req: ResidentKeyRequirement::Discouraged,
        extensions: AuthenticationExtensionsClientInputs {
            ..Default::default()
        },
        pin: None,
        use_ctap1_fallback: false,
    };

    let attestation_object;
    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager.register(10000, ctap_args, status_tx.clone(), callback) {
        panic!("Couldn't register: {:?}", e);
    };

    let register_result = register_rx
        .recv()
        .expect("Problem receiving, unable to continue");
    match register_result {
        Ok(a) => {
            println!("Ok!");
            attestation_object = a;
        }
        Err(e) => panic!("Registration failed: {:?}", e),
    };
    println!("{}", attestation_object.desc());
}
