use std::{
    sync::{
        mpsc::{channel, Sender},
        Arc, Mutex,
    },
    thread,
};

pub type Listener<T> = Box<dyn Fn(&T) -> bool + Send>;

pub struct ListenLoop<T: Send + 'static> {
    listeners: Arc<Mutex<Vec<Listener<T>>>>,
    data_tx: Sender<T>,
}

impl<T: Send + 'static> ListenLoop<T> {
    pub fn new() -> ListenLoop<T> {
        let (data_tx, data_rx) = channel::<T>();
        let listen_loop = ListenLoop {
            listeners: Arc::new(Mutex::new(vec![])),
            data_tx,
        };
        let listeners = listen_loop.listeners.clone();
        thread::spawn(move || loop {
            let data = match data_rx.recv() {
                Ok(x) => x,
                Err(_) => return,
            };
            let mut old_listeners = listeners.lock().unwrap();
            let mut new_listeners = vec![];
            while !old_listeners.is_empty() {
                match old_listeners.pop() {
                    Some(listener) => {
                        if !listener(&data) {
                            new_listeners.push(listener);
                        }
                    }
                    None => {}
                }
            }
            old_listeners.extend(new_listeners);
        });
        listen_loop
    }

    pub fn add_listener(&mut self, listener: Listener<T>) {
        self.listeners.lock().unwrap().push(listener);
    }

    pub fn sender(&self) -> Sender<T> {
        self.data_tx.clone()
    }
}
