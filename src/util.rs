use std::{
    fmt::Debug,
    sync::{Condvar, Mutex},
};

use base64::Engine;

pub fn base64_encode<T: AsRef<[u8]>>(v: T) -> String {
    base64::engine::general_purpose::STANDARD.encode(v)
}

pub fn abbreviate(id: &String, before: usize, after: usize) -> String {
    if id.len() <= before + 3 + after {
        return id.clone();
    }
    let first = &id[..=before];
    let second = &id[id.len() - after..id.len()];
    return first.to_string() + "..." + second;
}

pub fn display_option<T: Debug>(val: Option<T>) -> String {
    match val {
        Some(x) => format!("{:?}", x),
        None => "None".to_string(),
    }
}

pub fn b64_starts_with(v: &Vec<u8>, prefix: &String) -> bool {
    base64_encode(v).starts_with(prefix)
}

pub struct SetOnce<T: Clone> {
    val: Mutex<Option<T>>,
    cvar: Condvar,
}

impl<T: Clone> SetOnce<T> {
    pub fn new() -> SetOnce<T> {
        SetOnce {
            val: Mutex::new(None),
            cvar: Condvar::new(),
        }
    }

    pub fn set(&self, new_val: T) {
        let mut val = self.val.lock().unwrap();
        *val = Some(new_val);
        self.cvar.notify_all();
    }

    pub fn get(&self) -> T {
        let mut val = self.val.lock().unwrap();
        while (*val).is_none() {
            val = self.cvar.wait(val).unwrap();
        }
        val.clone().unwrap()
    }
}
