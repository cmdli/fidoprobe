mod custom_clone;
mod listen_loop;
mod manage_session;
mod pretty_desc;
mod status_listeners;
mod util;

use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    crypto::COSEAlgorithm,
    ctap2::server::{
        AuthenticationExtensionsClientInputs, PublicKeyCredentialParameters,
        PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement,
        UserVerificationRequirement,
    },
    statecallback::StateCallback,
    Pin,
};
use getopts::Options;
use listen_loop::ListenLoop;
use manage_session::ManageSession;
use pretty_desc::PrettyDesc;
use rand::{thread_rng, RngCore};
use status_listeners::{capture_pin_error, login_with_pin, prompt_for_presence};
use std::{
    env, io::{stdin, stdout, Write}, process::exit, sync::mpsc::{channel, Receiver}
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
static RP_NAME: &str = "webauthn.io";
static ORIGIN: &str = "https://webauthn.io";

static TIMEOUT: u64 = 10000;

fn prompt(msg: &str) -> Result<String, std::io::Error> {
    println!("{}", msg);
    print!("--> ");
    stdout().flush()?;
    let mut line = String::new();
    stdin().read_line(&mut line)?;
    Ok(line.trim_end().to_string())
}

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

fn list_credentials(pin: String) {
    let mut session = ManageSession::new(pin);
    let credentials = match session.list_credentials() {
        Ok(list) => list,
        Err(err) => {
            println!("Error: {}", err);
            return;
        }
    };
    if let Some(info) = session.auth_info() {
        println!("Authenticator: {:?}", info.aaguid);
    }
    println!("{}", credentials.desc());
}

fn get_credential(pin: String, prefix: String) {
    let mut session = ManageSession::new(pin);
    let res = session.get_credential(prefix);
    match res {
        Ok((cred, rp)) => println!("{}\n{}", rp.desc(), cred.desc()),
        Err(e) => println!("{}", e),
    }
}

fn delete_credential(pin: String, prefix: String) {
    let mut session = ManageSession::new(pin);
    if let Err(err) = session.delete_credential(prefix) {
        println!("Error: {}", err);
        return;
    }
    if let Some(info) = session.auth_info() {
        println!("Authenticator: {:?}", info.aaguid);
    }
    println!("Success");
}

fn get_assertion() {
    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();

    let (err_tx, err_rx) = channel();
    let mut listen_loop = ListenLoop::new();
    listen_loop.add_listener(capture_pin_error(err_tx));
    listen_loop.add_listener(prompt_for_presence());
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
    let result = result_rx.recv().expect("Failed to receive result");
    match result {
        Ok(result) => println!("{}", result.desc()),
        Err(err) => {
            if let Ok(err) = err_rx.try_recv() {
                println!("Error: {}", err);
            } else {
                println!("Error: {}", err);
            }
        }
    }
}

fn register_credential(pin: String) {
    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();

    let mut listen_loop = ListenLoop::new();
    listen_loop.add_listener(login_with_pin(pin));
    listen_loop.add_listener(prompt_for_presence());

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
        .expect("Problem receiving, unable to continue");
    match result {
        Ok(result) => {
            println!("{}", result.desc());
        }
        Err(x) => {
            println!("Unexpected error: {}", x);
        }
    }
}

fn set_pin(pin: String) {
    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();

    let mut listen_loop = ListenLoop::new();
    listen_loop.add_listener(prompt_for_presence());
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
    match result {
        Ok(()) => println!("Success"),
        Err(err) => {
            println!("Error: {}", err)
        }
    }
}

fn reset() {
    match prompt("Reset the authenticator (Y/n)?") {
        Ok(answer) => {
            if answer.to_lowercase() != "y" {
                return;
            }
        }
        Err(err) => {
            println!("Could not read response: {}", err);
            return;
        }
    }
    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();
    let mut listen_loop = ListenLoop::new();
    listen_loop.add_listener(prompt_for_presence());
    let (result_rx, callback) = callback_to_channel();
    manager.reset(TIMEOUT, listen_loop.sender(), callback).unwrap();
    let result = result_rx.recv().unwrap();
    match result {
        Ok(()) => println!("Success"),
        Err(err) => {
            println!("Error: {}", err)
        }
    }
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
            list_credentials(pin);
        }
        "set_pin" => {
            let pin = get_opt("pin");
            set_pin(pin);
        }
        "info" => {
            let pin = get_opt("pin");
            let prefix = get_free_arg(1, "No ID specified");
            get_credential(pin, prefix);
        }
        "delete" => {
            let pin = get_opt("pin");
            let prefix = get_free_arg(1, "No ID specified");
            delete_credential(pin, prefix);
        }
        "create" => {
            let pin = get_opt("pin");
            register_credential(pin);
        }
        "sign" => {
            get_assertion();
        }
        "reset" => {
            reset();
        }
        _ => println!("Unknown command: {}", command),
    }
}
