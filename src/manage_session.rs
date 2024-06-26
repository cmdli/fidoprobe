use crate::listen_loop::{ListenLoop, Listener};
use crate::status_listeners::{prompt_for_pin, prompt_for_presence};
use crate::util::b64_starts_with;
use crate::TIMEOUT;
use crate::{custom_clone::CustomClone, util::SetOnce};
use authenticator::ctap2::server::RelyingParty;
use authenticator::{
    authenticatorservice::AuthenticatorService,
    ctap2::commands::credential_management::{CredentialList, CredentialListEntry},
    statecallback::StateCallback,
    AuthenticatorInfo, CredManagementCmd, CredentialManagementResult, InteractiveRequest,
    InteractiveUpdate, StatusUpdate,
};
use std::sync::{
    mpsc::{channel, Sender},
    Arc, Mutex,
};

struct ManageSessionState {
    management_request: Option<Sender<InteractiveRequest>>,
    info: Option<AuthenticatorInfo>,
}

pub struct ManageSession {
    listen_loop: ListenLoop<StatusUpdate>,
    manager: Arc<Mutex<AuthenticatorService>>,
    state: Arc<Mutex<ManageSessionState>>,
    done: Arc<SetOnce<bool>>,
}

impl ManageSession {
    pub fn new() -> ManageSession {
        let mut manager =
            AuthenticatorService::new().expect("The auth service should initialize safely");
        manager.add_u2f_usb_hid_platform_transports();
        let mut session = ManageSession {
            listen_loop: ListenLoop::new(),
            manager: Arc::new(Mutex::new(manager)),
            done: Arc::new(SetOnce::new()),
            state: Arc::new(Mutex::new(ManageSessionState {
                management_request: None,
                info: None,
            })),
        };
        let (err_tx, _) = channel();
        session.add_listener(prompt_for_pin(err_tx));
        session.add_listener(prompt_for_presence());
        session.start();
        session
    }

    fn add_listener(&mut self, listener: Listener<StatusUpdate>) {
        self.listen_loop.add_listener(listener);
    }

    fn send_command(&mut self, cmd: InteractiveRequest) {
        let state = self.state.lock().unwrap();
        let sender = state.management_request.clone().unwrap();
        sender.send(cmd).unwrap();
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
        let done = self.done.clone();
        let callback = StateCallback::new(Box::new(move |_| {
            done.set(true);
        }));
        self.manager
            .lock()
            .unwrap()
            .manage(TIMEOUT, self.listen_loop.sender(), callback)
            .unwrap();
        done_rx.recv().unwrap();
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
        self.send_command(InteractiveRequest::CredentialManagement(
            CredManagementCmd::GetCredentials,
            None,
        ));
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
        let command = CredManagementCmd::DeleteCredential(credential.credential_id.clone());
        self.send_command(InteractiveRequest::CredentialManagement(command, None));
        result_rx.recv().unwrap()
    }
}

impl Drop for ManageSession {
    fn drop(&mut self) {
        self.send_command(InteractiveRequest::Quit);
        self.done.get();
    }
}
