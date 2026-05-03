use crate::store::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareEvent {
    pub connection_id: EventId,
    pub message: Vec<u8>,
}
