use super::codec::{BucketSummary, BUCKETS};
use crate::store::EventId;

pub fn differing_buckets(
    local: &[BucketSummary; BUCKETS],
    remote: &[BucketSummary; BUCKETS],
) -> Vec<u8> {
    local
        .iter()
        .zip(remote.iter())
        .enumerate()
        .filter_map(|(idx, (left, right))| (left != right).then_some(idx as u8))
        .collect()
}

pub fn missing_ids(local_has: impl Fn(&EventId) -> bool, remote_ids: &[EventId]) -> Vec<EventId> {
    remote_ids
        .iter()
        .copied()
        .filter(|id| !local_has(id))
        .collect()
}
