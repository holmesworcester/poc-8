use crate::store::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HaveIdEvent {
    pub connection_id: EventId,
    pub id: EventId,
}
