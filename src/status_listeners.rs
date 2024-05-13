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

pub fn panic_on_pin_error() -> Listener<StatusUpdate> {
    Box::new(move |update| match update {
        StatusUpdate::PinUvError(e) => {
            panic!("Unexpected PIN error: {:?}", e);
        }
        _ => false,
    })
}

pub fn login_with_pin(pin: String) -> Listener<StatusUpdate> {
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
