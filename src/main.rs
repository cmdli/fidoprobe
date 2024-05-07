mod pretty_desc;

use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs}, crypto::COSEAlgorithm, ctap2::{commands::credential_management::CredentialList,  server::{
        AuthenticationExtensionsClientInputs, PublicKeyCredentialParameters,
        PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement,
        UserVerificationRequirement,
    }}, errors::AuthenticatorError, statecallback::StateCallback, CredManagementCmd::GetCredentials, CredentialManagementResult, InteractiveRequest::{CredentialManagement, Quit}, InteractiveUpdate, Pin, StatusPinUv, StatusUpdate
};
use pretty_desc::PrettyDesc;
use rand::{thread_rng, RngCore};
use std::{
    sync::mpsc::{channel, RecvError, Sender},
    thread::{self, spawn},
};

/*
Usages:
    - Create a credential
    - List credentials on device for an origin
    - Get assertion of credential (possibly for a specified challenge)

Requirements:
    - Pretty print all results
*/
static USERNAME: &str = "username";
static USER_ID: &str = "userid";
static RP_NAME: &str = "Example";
static ORIGIN: &str = "https://example.com";
static DEFAULT_PIN: &str = "1234";

static TIMEOUT: u64 = 10000;

fn list_credentials(manager: &mut AuthenticatorService) {
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || {
        let mut management_request = None;
        loop {
            match status_rx.recv() {
                Ok(StatusUpdate::InteractiveManagement(InteractiveUpdate::StartManagement((request, _)))) => {
                    management_request = Some(request.clone());
                    if let Some(sender) = management_request.clone() {
                        sender.send(CredentialManagement(GetCredentials, None)).unwrap();
                    }
                },
                Ok(StatusUpdate::InteractiveManagement(InteractiveUpdate::CredentialManagementUpdate((result, _)))) => {
                    println!("{}", result.desc());
                    if let Some(sender) = management_request.clone() {
                        sender.send(Quit).unwrap();
                    }
                },
                Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(response))) => {
                    response.send(Pin::new(DEFAULT_PIN)).unwrap();
                },
                Err(_) => {
                    println!("STATUS: END");
                    return
                }
                x => {println!("Unknown Update: {:?}",x)},
            }
        }
    });

    let (receive_tx, receive_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        receive_tx.send(rv).unwrap();
    }));

    manager.manage(TIMEOUT, status_tx, callback).unwrap();

    receive_rx.recv().expect("List Credentials failed").unwrap();
}

fn get_assertion(manager: &mut AuthenticatorService) {
    let status_tx = spawn_status_listener();
    let args = SignArgs {
        client_data_hash: (0..=31)
            .collect::<Vec<u8>>()
            .try_into()
            .expect("Invalid array size"),
        origin: ORIGIN.to_string(),
        relying_party_id: RP_NAME.to_string(),
        allow_list: vec![],
        user_verification_req: UserVerificationRequirement::Preferred,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs {
            ..Default::default()
        },
        pin: None,
        use_ctap1_fallback: false,
    };

    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager.sign(TIMEOUT, args, status_tx, callback) {
        panic!("Error: {}", e);
    }

    let result;
    match register_rx.recv().expect("Failed to receive result") {
        Ok(a) => {
            result = a;
        }
        Err(e) => {
            panic!("{}", e)
        }
    }
    println!("{}", result.desc());
}

fn register_credential(manager: &mut AuthenticatorService) {
    let status_tx = spawn_status_listener();

    let mut chall_bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut chall_bytes);

    let user = PublicKeyCredentialUserEntity {
        id: USER_ID.as_bytes().to_vec(),
        name: Some(USERNAME.to_string()),
        display_name: None,
    };
    let relying_party = RelyingParty {
        id: RP_NAME.to_string(),
        name: None,
    };
    let ctap_args = RegisterArgs {
        client_data_hash: chall_bytes,
        relying_party,
        origin: ORIGIN.to_string(),
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
        resident_key_req: ResidentKeyRequirement::Preferred,
        extensions: AuthenticationExtensionsClientInputs {
            ..Default::default()
        },
        pin: None,
        use_ctap1_fallback: false,
    };

    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager.register(TIMEOUT, ctap_args, status_tx.clone(), callback) {
        panic!("Couldn't register: {:?}", e);
    };

    let result = register_rx
        .recv()
        .expect("Problem receiving, unable to continue")
        .expect("Registration failed");
    println!("{}", result.desc());
}

fn spawn_status_listener() -> std::sync::mpsc::Sender<StatusUpdate> {
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
    status_tx
}

fn set_pin(manager: &mut AuthenticatorService) {
    let status_tx = spawn_status_listener();
    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));
    manager.set_pin(TIMEOUT, Pin::new(DEFAULT_PIN), status_tx, callback).unwrap();
    let result = register_rx.recv().unwrap();
    println!("Set Pin Result: {:?}", result);
}

fn main() {
    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();


    // get_assertion(&mut manager);
    list_credentials(&mut manager);
    // set_pin(&mut manager);
}
