use std::sync::OnceLock;

static GADGET: OnceLock<usize> = OnceLock::new();

pub(crate) fn cache(ptr: *const u8) {
    GADGET.get_or_init(|| ptr as usize);
}
