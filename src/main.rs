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
        AuthenticationExtensionsClientInputs, PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement, UserVerificationRequirement
    },
    statecallback::StateCallback,
    Pin,
};
use clap::{Parser, Subcommand};
use listen_loop::ListenLoop;
use manage_session::ManageSession;
use pretty_desc::PrettyDesc;
use rand::{thread_rng, RngCore};
use status_listeners::{capture_pin_error, prompt_for_pin, prompt_for_presence};
use std::sync::mpsc::{channel, Receiver};
use util::prompt;

/*
Usages:
    - Create a credential
    - List credentials on device for an origin
    - Get assertion of credential (possibly for a specified challenge)

Requirements:
    - Pretty print all results
*/
static RP_NAME: &str = "webauthn.io";
static ORIGIN: &str = "https://webauthn.io";

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

fn list_credentials() {
    let mut session = ManageSession::new();
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

fn get_credential(prefix: String) {
    let mut session = ManageSession::new();
    let res = session.get_credential(prefix);
    match res {
        Ok((cred, rp)) => println!("{}\n{}", rp.desc(), cred.desc()),
        Err(e) => println!("{}", e),
    }
}

fn delete_credential(prefix: String) {
    let mut session = ManageSession::new();
    if let Err(err) = session.delete_credential(prefix) {
        println!("Error: {}", err);
        return;
    }
    if let Some(info) = session.auth_info() {
        println!("Authenticator: {:?}", info.aaguid);
    }
    println!("Success");
}

fn get_assertion(_id: String) {
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

fn register_credential(user_id: String, user_name: String, rp_id: String, origin: String) {
    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();

    let (err_tx, err_rx) = channel();
    let mut listen_loop = ListenLoop::new();
    listen_loop.add_listener(prompt_for_pin(err_tx));
    listen_loop.add_listener(prompt_for_presence());

    let mut chall_bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut chall_bytes);

    let user = PublicKeyCredentialUserEntity {
        id: user_id.as_bytes().to_vec(),
        name: Some(user_name),
        display_name: None,
    };
    let relying_party = RelyingParty {
        id: rp_id,
        name: None,
    };
    let ctap_args = RegisterArgs {
        client_data_hash: chall_bytes,
        relying_party,
        origin,
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
            if let Ok(err) = err_rx.try_recv() {
                println!("Error: {}", err);
            } else {
                println!("Unexpected error: {}", x);
            }
        }
    }
}

fn set_pin() {
    let pin = match rpassword::prompt_password("Enter new PIN: ") {
        Ok(pin) => pin.trim_end().to_string(),
        Err(err) => {
            println!("Error: {}", err);
            return;
        }
    };

    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();

    let (err_tx, err_rx) = channel();
    let mut listen_loop = ListenLoop::new();
    listen_loop.add_listener(prompt_for_pin(err_tx));
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
            if let Ok(err) = err_rx.try_recv() {
                println!("Error: {}", err);
            } else {
                println!("Error: {}", err);
            }
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
    manager
        .reset(TIMEOUT, listen_loop.sender(), callback)
        .unwrap();
    let result = result_rx.recv().unwrap();
    match result {
        Ok(()) => println!("Success"),
        Err(err) => {
            println!("Error: {}", err)
        }
    }
}

#[derive(Parser, Debug)]
#[command(about = "A utility to interact with FIDO2 devices")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(
        about = "List credentials",
        long_about = "List credentials for an authenticator"
    )]
    List {},
    #[command(about = "Get info for a particular credential")]
    Info {
        #[arg(
            required = true,
            help = "ID of the credential in base64 (accepts prefixes, e.g. \"iJ7xQ\")"
        )]
        id: String,
    },
    #[command(about = "Create a new credential")]
    Create {
        #[arg(long, value_name = "ID", help = "ID of the user (e.g. \"aLiCe\")", default_value_t = String::from("user_id"))]
        id: String,
        #[arg(long, help = "Name of the user", default_value_t = String::from("username"))]
        name: String,
        #[arg(
            long,
            help = "ID of the relying party (usually a website, e.g. \"webauthn.io\")",
            default_value_t = String::from("example.com")
        )]
        rp: String,
        #[arg(
            long,
            help = "Website origin of the relying party (e.g. \"example.com\")",
            default_value_t = String::from("example.com")
        )]
        origin: String,
    },
    #[command(about = "Delete a credential")]
    Delete {
        #[arg(
            required = true,
            help = "ID of the credential in base64 (accepts prefixes, e.g. \"iJ7xQ\")"
        )]
        id: String,
    },
    #[command(about = "Set the PIN on an authenticator")]
    SetPin {},
    #[command(about = "Reset an authenticator")]
    Reset {},
    #[command(about = "Sign a challenge with a credential")]
    Sign { id: String },
}

fn main() {
    let args = Args::parse();
    match args.command {
        Commands::List {} => {
            list_credentials();
        }
        Commands::SetPin {} => {
            set_pin();
        }
        Commands::Info { id } => {
            get_credential(id);
        }
        Commands::Delete { id } => {
            delete_credential(id);
        }
        Commands::Create {
            id,
            name,
            rp,
            origin,
        } => {
            register_credential(id, name, rp, origin);
        }
        Commands::Sign { id } => {
            get_assertion(id);
        }
        Commands::Reset {} => {
            reset();
        }
    }
}
