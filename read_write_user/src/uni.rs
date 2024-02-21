use windows::core::PCWSTR;

pub struct OwnedString {
    _s: String,
    buf: Vec<u16>,
    _phantom_pinned: std::marker::PhantomPinned,
}

impl OwnedString {
    pub fn as_pcwstr(&self) -> PCWSTR {
        PCWSTR::from_raw(self.buf.as_ptr() as _)
    }
}

pub fn owned_string_from_str(s: &str) -> OwnedString {
    let mut buf = Vec::with_capacity(s.encode_utf16().count() + 1);
    buf.extend(s.encode_utf16());
    buf.push(0);
    OwnedString {
        _s: s.to_string(),
        buf,
        _phantom_pinned: std::marker::PhantomPinned,
    }
}
