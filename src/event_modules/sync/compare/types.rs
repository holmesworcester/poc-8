use crate::store::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareEvent {
    pub connection_id: EventId,
    pub sender_is_initiator: bool,
    pub message: Vec<u8>,
}
