mod pretty_desc;

use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    crypto::COSEAlgorithm,
    ctap2::{
        commands::credential_management::CredentialList,
        server::{
            AuthenticationExtensionsClientInputs, PublicKeyCredentialParameters,
            PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement,
            UserVerificationRequirement,
        },
    },
    statecallback::StateCallback,
    CredManagementCmd::GetCredentials,
    CredentialManagementResult,
    InteractiveRequest::{CredentialManagement, Quit},
    InteractiveUpdate::{CredentialManagementUpdate, StartManagement},
    Pin, StatusPinUv,
    StatusUpdate::{self, InteractiveManagement, PinUvError},
};
use getopts::Options;
use pretty_desc::PrettyDesc;
use rand::{thread_rng, RngCore};
use std::{
    env,
    ops::Deref,
    sync::{
        mpsc::{channel, Receiver, RecvError, Sender},
        Arc, Mutex,
    },
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
static USERNAME: &str = "username";
static USER_ID: &str = "userid";
static RP_NAME: &str = "Example";
static ORIGIN: &str = "https://example.com";

static TIMEOUT: u64 = 10000;

fn callback_to_channel<T>() -> (Receiver<T>, StateCallback<T>)
where
    T: Send + 'static,
{
    let (receive_tx, receive_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        receive_tx.send(rv).unwrap();
    }));
    (receive_rx, callback)
}

fn update_listener(listener: Box<dyn Fn(StatusUpdate) + Send>) -> Sender<StatusUpdate> {
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        let status = match status_rx.recv() {
            Ok(x) => x,
            Err(_) => return,
        };
        listener(status);
    });
    status_tx
}

fn list_credentials(
    manager: &mut AuthenticatorService,
    pin: String,
) -> Result<CredentialList, &str> {
    let (result_tx, result_rx) = channel::<Result<CredentialList, &str>>();
    let req = Arc::new(Mutex::new(None));
    let status_tx = update_listener(Box::new(move |status| match status {
        InteractiveManagement(interactive) => match interactive {
            StartManagement((request, _)) => {
                req.lock().unwrap().replace(request.clone());
                request
                    .send(CredentialManagement(GetCredentials, None))
                    .unwrap();
            }
            CredentialManagementUpdate((CredentialManagementResult::CredentialList(list), _)) => {
                if let Err(e) = result_tx.send(Ok(list)) {
                    println!("Error sending result: {}", e);
                }
                match req.lock().unwrap().deref() {
                    Some(sender) => sender.send(Quit).unwrap(),
                    None => {}
                }
            }
            x => println!("Unknown InteractiveManagement: {:?}", x),
        },
        PinUvError(err) => match err {
            StatusPinUv::PinRequired(response) => {
                response.send(Pin::new(pin.as_str())).unwrap();
            }
            StatusPinUv::InvalidPin(_, _) => {
                result_tx.send(Err("Invalid PIN")).unwrap();
                return;
            }
            x => println!("Unknown PinUvError: {:?}", x),
        },
        x => println!("Unknown Update: {:?}", x),
    }));

    let (receive_rx, callback) = callback_to_channel();

    manager.manage(TIMEOUT, status_tx, callback).unwrap();

    receive_rx
        .recv()
        .unwrap()
        .or(Err("Could not receive result"))?;

    result_rx.recv().unwrap()
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

    let (result_rx, callback) = callback_to_channel();
    manager.register(TIMEOUT, ctap_args, status_tx.clone(), callback).expect("Could not call register");
    let result = result_rx
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

fn set_pin(manager: &mut AuthenticatorService, pin: String) {
    let status_tx = spawn_status_listener();
    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));
    manager
        .set_pin(TIMEOUT, Pin::new(pin.as_str()), status_tx, callback)
        .unwrap();
    let result = register_rx.recv().unwrap();
    println!("Set Pin Result: {:?}", result);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();
    opts.optopt(
        "c",
        "command",
        "command to run",
        "list, set_pin, create, sign",
    );
    opts.optopt("", "pin", "PIN for the device", "1234");
    let matches = opts.parse(&args[1..]).expect("Could not parse options");

    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();

    let mut pin = None;
    match matches.opt_get::<String>("pin") {
        Ok(Some(pin_string)) => {
            pin = Some(pin_string);
        }
        _ => {}
    }

    match matches.opt_get::<String>("c") {
        Ok(Some(command)) => match command.as_str() {
            "list" => match list_credentials(&mut manager, pin.expect("No PIN provided")) {
                Ok(list) => {
                    println!("{}", list.desc())
                }
                Err(e) => {
                    println!("Could not list credentials: {}", e)
                }
            },
            "set_pin" => {
                set_pin(&mut manager, pin.expect("No PIN Provided"));
            }
            "create" => {
                register_credential(&mut manager);
            }
            "sign" => {
                get_assertion(&mut manager);
            }
            _ => println!("Unknown command: {}", command),
        },
        Ok(None) => println!("No command set"),
        Err(x) => println!("Error: {}", x),
    }
}
