use crate::util::b64_starts_with;
use crate::TIMEOUT;
use crate::{custom_clone::CustomClone, util::SetOnce};
use authenticator::ctap2::server::RelyingParty;
use authenticator::{
    authenticatorservice::AuthenticatorService,
    ctap2::commands::credential_management::{CredentialList, CredentialListEntry},
    statecallback::StateCallback,
    AuthenticatorInfo, CredManagementCmd, CredentialManagementResult, InteractiveRequest,
    InteractiveUpdate, Pin, StatusPinUv, StatusUpdate,
};
use std::{
    sync::{
        mpsc::{channel, Sender},
        Arc, Mutex,
    },
    thread,
};

type UpdateListener = Box<dyn Fn(&StatusUpdate) -> bool + Send>;

struct ManageSessionState {
    management_request: Option<Sender<InteractiveRequest>>,
    info: Option<AuthenticatorInfo>,
    error: Option<String>,
}

pub struct ManageSession {
    listeners: Arc<Mutex<Vec<UpdateListener>>>,
    manager: Arc<Mutex<AuthenticatorService>>,
    state: Arc<Mutex<ManageSessionState>>,
    done: Arc<SetOnce<bool>>,
}

impl ManageSession {
    pub fn new(pin: String) -> ManageSession {
        let mut manager =
            AuthenticatorService::new().expect("The auth service should initialize safely");
        manager.add_u2f_usb_hid_platform_transports();
        let mut session = ManageSession {
            listeners: Arc::new(Mutex::new(vec![])),
            manager: Arc::new(Mutex::new(manager)),
            done: Arc::new(SetOnce::new()),
            state: Arc::new(Mutex::new(ManageSessionState {
                management_request: None,
                info: None,
                error: None,
            })),
        };
        session.add_pin_listener(pin);
        session.start();
        session
    }

    fn add_pin_listener(&mut self, pin: String) {
        let state = self.state.clone();
        self.add_listener(Box::new(move |update| match update {
            StatusUpdate::PinUvError(err) => match err {
                StatusPinUv::PinRequired(response) => {
                    response.send(Pin::new(pin.as_str())).unwrap();
                    false
                }
                StatusPinUv::InvalidPin(_, _) => {
                    state
                        .lock()
                        .unwrap()
                        .error
                        .replace("Invalid PIN".to_string());
                    true
                }
                x => {
                    println!("Unknown PIN update: {:?}", x);
                    false
                }
            },
            _ => false,
        }));
    }

    fn start_update_listen(&self) -> Sender<StatusUpdate> {
        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let listeners = self.listeners.clone();
        thread::spawn(move || loop {
            let status = match status_rx.recv() {
                Ok(x) => x,
                Err(_) => return,
            };
            let mut old_listeners = listeners.lock().unwrap();
            let mut new_listeners = vec![];
            while !old_listeners.is_empty() {
                match old_listeners.pop() {
                    Some(listener) => {
                        if !listener(&status) {
                            new_listeners.push(listener);
                        }
                    }
                    None => {}
                }
            }
            old_listeners.extend(new_listeners);
        });
        status_tx
    }

    fn add_listener(&mut self, listener: UpdateListener) {
        self.listeners.lock().unwrap().push(listener);
    }

    fn send_command(&mut self, cmd: InteractiveRequest) {
        let state = self.state.lock().unwrap();
        let sender = state.management_request.clone().unwrap();
        sender.send(cmd).unwrap();
    }

    fn send_management_command(&mut self, cmd: CredManagementCmd) {
        self.send_command(InteractiveRequest::CredentialManagement(cmd, None))
    }

    pub fn auth_info(&self) -> Option<AuthenticatorInfo> {
        let state = self.state.lock().unwrap();
        state.info.clone()
    }

    fn start(&mut self) {
        let (done_tx, done_rx) = channel();
        let state = self.state.clone();
        self.add_listener(Box::new(move |update| match update {
            StatusUpdate::InteractiveManagement(InteractiveUpdate::StartManagement((
                req,
                info,
            ))) => {
                let mut state = state.lock().unwrap();
                if let Some(info) = info {
                    state.info.replace(info.clone());
                }
                state.management_request.replace(req.clone());
                done_tx.send(true).unwrap();
                true
            }
            _ => false,
        }));
        let status_tx = self.start_update_listen();
        let done = self.done.clone();
        let callback = StateCallback::new(Box::new(move |_| {
            done.set(true);
        }));
        self.manager
            .lock()
            .unwrap()
            .manage(TIMEOUT, status_tx, callback)
            .unwrap();
        done_rx.recv().unwrap();
    }

    pub fn wait(&self) {
        self.done.get();
    }

    pub fn list_credentials(&mut self) -> Result<CredentialList, String> {
        let (result_tx, result_rx) = channel();
        self.add_listener(Box::new(move |update| match update {
            StatusUpdate::InteractiveManagement(InteractiveUpdate::CredentialManagementUpdate(
                (CredentialManagementResult::CredentialList(list), _),
            )) => {
                let c_list = (*list).custom_clone();
                result_tx.send(Ok(c_list)).unwrap();
                true
            }
            _ => false,
        }));
        self.send_management_command(CredManagementCmd::GetCredentials);
        result_rx.recv().unwrap()
    }

    pub fn get_credential(
        &mut self,
        prefix: String,
    ) -> Result<(CredentialListEntry, RelyingParty), String> {
        let credentials = self.list_credentials()?;
        for rp_entry in credentials.credential_list {
            for entry in rp_entry.credentials {
                if b64_starts_with(&entry.credential_id.id, &prefix) {
                    return Ok((entry, rp_entry.rp.clone()));
                }
            }
        }
        Err("Could not find credential".to_string())
    }

    pub fn delete_credential(&mut self, prefix: String) -> Result<(), String> {
        let (credential, _) = self.get_credential(prefix)?;
        let (result_tx, result_rx) = channel();
        self.add_listener(Box::new(move |update| match update {
            StatusUpdate::InteractiveManagement(InteractiveUpdate::CredentialManagementUpdate(
                (CredentialManagementResult::DeleteSucess, _),
            )) => {
                result_tx.send(Ok(())).unwrap();
                true
            }
            _ => false,
        }));
        self.send_management_command(CredManagementCmd::DeleteCredential(
            credential.credential_id.clone(),
        ));
        result_rx.recv().unwrap()
    }
}

impl Drop for ManageSession {
    fn drop(&mut self) {
        self.send_command(InteractiveRequest::Quit);
        self.wait();
    }
}
