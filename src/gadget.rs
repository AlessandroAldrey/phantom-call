use std::sync::OnceLock;

static GADGET: OnceLock<usize> = OnceLock::new();

pub(crate) fn cache(ptr: *const u8) {
    GADGET.get_or_init(|| ptr as usize);
}

pub(crate) fn get() -> Option<*const u8> {
    GADGET.get().map(|&addr| addr as *const u8)
}
