use std::sync::mpsc::Sender;

use authenticator::{Pin, StatusPinUv, StatusUpdate};

use crate::listen_loop::Listener;

pub fn prompt_for_presence() -> Listener<StatusUpdate> {
    Box::new(move |update| match update {
        StatusUpdate::SelectDeviceNotice => {
            println!("Multiple devices detected, please confirm on the desired device...");
            false
        }
        StatusUpdate::PresenceRequired => {
            println!("User presence required, please confirm on desired device...");
            false
        }
        _ => false,
    })
}

pub fn capture_pin_error(err: Sender<String>) -> Listener<StatusUpdate> {
    Box::new(move |update| match update {
        StatusUpdate::PinUvError(err_status) => {
            let msg = match err_status {
                StatusPinUv::PinRequired(_) => "PIN Required".to_string(),
                StatusPinUv::InvalidPin(..) => "Invalid PIN".to_string(),
                StatusPinUv::PinBlocked => "PIN Blocked".to_string(),
                StatusPinUv::PinIsTooLong(size) => format!("PIN is too long, max length {}", size),
                StatusPinUv::PinIsTooShort => "PIN is too short".to_string(),
                _ => format!("PIN Error: {:?}", err_status),
            };
            err.send(msg).unwrap();
            true
        }
        _ => false,
    })
}

pub fn _login_with_pin(pin: String) -> Listener<StatusUpdate> {
    // TODO: Handle PIN errors better
    Box::new(move |update| match update {
        StatusUpdate::PinUvError(err) => match err {
            StatusPinUv::PinRequired(response) => {
                response.send(Pin::new(pin.as_str())).unwrap();
                false
            }
            StatusPinUv::InvalidPin(_, _) => {
                println!("Invalid PIN specified");
                true
            }
            // TODO: Handle the PIN error messages
            x => {
                println!("Unknown PIN update: {:?}", x);
                false
            }
        },
        _ => false,
    })
}

pub fn prompt_for_pin(err_tx: Sender<String>) -> Listener<StatusUpdate> {
    Box::new(move |update| match update {
        StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
            match rpassword::prompt_password("Enter PIN: ") {
                Ok(pin) => {
                    sender.send(Pin::new(pin.trim_end())).unwrap();
                    false
                }
                Err(err) => {
                    err_tx.send(err.to_string()).unwrap();
                    true
                }
            }
        }
        StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts)) => {
            match attempts {
                Some(attempts) => println!("Invalid PIN, {} attempts remaining", attempts),
                None => println!("Invalid PIN"),
            }
            match rpassword::prompt_password("Enter PIN: ") {
                Ok(pin) => {
                    sender.send(Pin::new(pin.trim_end())).unwrap();
                    false
                }
                Err(err) => {
                    err_tx.send(err.to_string()).unwrap();
                    true
                }
            }
        }
        StatusUpdate::PinUvError(StatusPinUv::PinIsTooLong(size)) => {
            err_tx
                .send(format!("PIN is too long (max length {})", size))
                .unwrap();
            true
        }
        StatusUpdate::PinUvError(StatusPinUv::PinIsTooShort) => {
            err_tx.send("PIN is too short".to_string()).unwrap();
            true
        }
        _ => false,
    })
}
