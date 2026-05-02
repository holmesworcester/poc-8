use super::codec::{BucketSummary, BUCKETS};

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
