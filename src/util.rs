use base64::Engine;

pub fn base64_encode<T: AsRef<[u8]>>(v: T) -> String {
    base64::engine::general_purpose::STANDARD.encode(v)
}
