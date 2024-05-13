mod custom_clone;
mod listen_loop;
mod manage_session;
mod pretty_desc;
mod status_listeners;
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
    AuthenticatorInfo, Pin, StatusUpdate,
};
use getopts::Options;
use listen_loop::ListenLoop;
use manage_session::ManageSession;
use pretty_desc::PrettyDesc;
use rand::{thread_rng, RngCore};
use status_listeners::{panic_on_pin_error, prompt_for_presence};
use std::{
    env,
    process::exit,
    sync::mpsc::{channel, Receiver},
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

fn list_credentials(pin: String) -> Result<(CredentialList, Option<AuthenticatorInfo>), String> {
    let mut session = ManageSession::new(pin);
    let credentials = session.list_credentials()?;
    let info = session.auth_info();
    Ok((credentials, info))
}

fn get_credential(
    pin: String,
    prefix: String,
) -> Result<(CredentialListEntry, RelyingParty), String> {
    let mut session = ManageSession::new(pin);
    let res = session.get_credential(prefix);
    res
}

fn delete_credential(pin: String, prefix: String) -> Result<Option<AuthenticatorInfo>, String> {
    let mut session = ManageSession::new(pin);
    session.delete_credential(prefix)?;
    Ok(session.auth_info())
}

fn get_assertion(manager: &mut AuthenticatorService) {
    let listen_loop = default_listen_loop();
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
    manager
        .sign(TIMEOUT, args, listen_loop.sender(), callback)
        .unwrap();
    let result = result_rx.recv().expect("Failed to receive result").unwrap();
    println!("{}", result.desc());
}

fn register_credential(manager: &mut AuthenticatorService) {
    let listen_loop = default_listen_loop();

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
        .register(TIMEOUT, ctap_args, listen_loop.sender(), callback)
        .unwrap();
    let result = result_rx
        .recv()
        .expect("Problem receiving, unable to continue")
        .expect("Registration failed");
    println!("{}", result.desc());
}

fn default_listen_loop() -> ListenLoop<StatusUpdate> {
    let mut listen_loop = ListenLoop::new();
    listen_loop.add_listener(panic_on_pin_error());
    listen_loop.add_listener(prompt_for_presence());
    listen_loop
}

fn set_pin(manager: &mut AuthenticatorService, pin: String) {
    let listen_loop = default_listen_loop();
    let (result_rx, callback) = callback_to_channel();
    manager
        .set_pin(
            TIMEOUT,
            Pin::new(pin.as_str()),
            listen_loop.sender(),
            callback,
        )
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

    let get_opt = |name: &str| {
        let val = &matches.opt_str(name);
        if let None = val {
            println!("Option required: {}", name);
            print_usage(program, &opts);
            exit(1);
        }
        val.clone().unwrap()
    };

    let get_free_arg = |i: usize, err_msg: &str| {
        if (&matches).free.len() <= i {
            println!("{}", err_msg);
            print_usage(program, &opts);
            exit(1);
        }
        (&matches).free[i].clone()
    };

    let command = get_free_arg(0, "No command specified");

    match command.as_str() {
        "list" => {
            let pin = get_opt("pin");
            let res = list_credentials(pin);
            match res {
                Err(e) => {
                    println!("Could not list credentials: {}", e);
                }
                Ok((list, info)) => {
                    if let Some(info) = info {
                        println!("Authenticator: {:?}", info.aaguid);
                    }
                    println!("{}", list.desc());
                }
            }
        }
        "set_pin" => {
            let pin = get_opt("pin");
            set_pin(&mut manager, pin);
        }
        "info" => {
            let pin = get_opt("pin");
            let prefix = get_free_arg(1, "No ID specified");
            let cred = get_credential(pin, prefix);
            match cred {
                Ok((cred, rp)) => println!("{}\n{}", rp.desc(), cred.desc()),
                Err(e) => println!("{}", e),
            }
        }
        "delete" => {
            let pin = get_opt("pin");
            let prefix = get_free_arg(1, "No ID specified");
            match delete_credential(pin, prefix) {
                Ok(info) => {
                    if let Some(info) = info {
                        println!("Authenticator: {:?}", info.aaguid);
                    }
                    println!("Success");
                }
                Err(e) => {
                    println!("Error: {}", e);
                }
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
