pub mod compare;
pub mod have;
pub mod need;

pub use compare::{
    decode as decode_compare, encode as encode_sync_compare, project as project_compare,
    SyncCompareEvent,
};
pub use have::{
    decode as decode_have, encode as encode_sync_have, project as project_have, SyncHaveEvent,
};
pub use need::{
    decode as decode_need, encode as encode_sync_need, project as project_need, SyncNeedEvent,
};

pub const TYPE_COMPARE: u8 = compare::TYPE_CODE;
pub const TYPE_HAVE: u8 = have::TYPE_CODE;
pub const TYPE_NEED: u8 = need::TYPE_CODE;
pub const COMPARE_TYPE_NAME: &str = compare::TYPE_NAME;
pub const HAVE_TYPE_NAME: &str = have::TYPE_NAME;
pub const NEED_TYPE_NAME: &str = need::TYPE_NAME;
pub const TABLES: &[&str] = &[compare::TABLE, have::TABLE, need::TABLE];
