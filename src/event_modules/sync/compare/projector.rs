pub fn has_payload(message: &[u8]) -> bool {
    !message.is_empty()
}
