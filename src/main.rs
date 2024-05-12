mod pretty_desc;
mod util;

use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    crypto::COSEAlgorithm,
    ctap2::{
        commands::credential_management::{CredentialList, CredentialListEntry},
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
    process::exit,
    sync::{
        mpsc::{channel, Receiver, RecvError, Sender},
        Arc, Mutex,
    },
    thread,
};
use util::base64_encode;

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

fn list_credentials<'a>(
    manager: &'a mut AuthenticatorService,
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

    receive_rx.recv().unwrap().ok();

    result_rx.recv().unwrap_or(Err("Unexpectedly quit"))
}

fn b64_starts_with(v: &Vec<u8>, prefix: &String) -> bool {
    base64_encode(v).starts_with(prefix)
}

fn get_credential(
    manager: &mut AuthenticatorService,
    pin: String,
    prefix: String,
) -> Result<CredentialListEntry, &str> {
    list_credentials(manager, pin)?
        .credential_list
        .into_iter()
        .flat_map(|entry| entry.credentials.into_iter())
        .find(|cred| b64_starts_with(&cred.credential_id.id, &prefix))
        .ok_or("Could not find credential")
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

    let (result_rx, callback) = callback_to_channel();
    manager.sign(TIMEOUT, args, status_tx, callback).unwrap();
    let result = result_rx.recv().expect("Failed to receive result").unwrap();
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
    manager
        .register(TIMEOUT, ctap_args, status_tx.clone(), callback)
        .unwrap();
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
    let (result_rx, callback) = callback_to_channel();
    manager
        .set_pin(TIMEOUT, Pin::new(pin.as_str()), status_tx, callback)
        .unwrap();
    let result = result_rx.recv().unwrap();
    println!("Set Pin Result: {:?}", result);
}

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {program} [OPTIONS] COMMAND");
    println!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];
    let mut opts = Options::new();
    opts.optflag("h", "help", "Display this help message");
    opts.optopt("", "pin", "PIN for the device", "1234");
    opts.optopt(
        "",
        "id",
        "ID of the credential (accepts unique prefixes)",
        "x91m3",
    );
    let matches = opts.parse(&args[1..]).expect("Could not parse options");

    if matches.opt_present("h") {
        print_usage(program, &opts);
        return;
    }

    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();

    let command = if matches.free.is_empty() {
        println!("No command specified");
        print_usage(program, &opts);
        return;
    } else {
        matches.free[0].clone()
    };

    let get_opt = |name: &str| {
        let val = &matches.opt_str(name);
        if let None = val {
            println!("Option required: {}", name);
            print_usage(program, &opts);
            exit(1);
        }
        val.clone().unwrap()
    };

    match command.as_str() {
        "list" => {
            let pin = get_opt("pin");
            let res = list_credentials(&mut manager, pin);
            if let Err(e) = res {
                println!("Could not list credentials: {}", e);
            } else {
                println!("{}", res.unwrap().desc())
            }
        }
        "set_pin" => {
            let pin = get_opt("pin");
            set_pin(&mut manager, pin);
        }
        "info" => {
            let pin = get_opt("pin");
            let prefix = get_opt("id");
            let cred = get_credential(&mut manager, pin, prefix);
            if let Err(e) = cred {
                println!("{}", e);
            } else {
                println!("{}", cred.unwrap().desc());
            }
        }
        "create" => {
            register_credential(&mut manager);
        }
        "sign" => {
            get_assertion(&mut manager);
        }
        _ => println!("Unknown command: {}", command),
    }
}
