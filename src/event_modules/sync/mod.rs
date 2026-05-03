pub mod compare;
pub mod data;
pub mod frame;
pub mod have_id;
pub mod jobs;
pub mod need_id;
pub mod negentropy;

use crate::store::ProjectionOutput;

pub fn project_record(bytes: &[u8]) -> Result<Option<ProjectionOutput>, String> {
    if frame::codec::is_frame(bytes) {
        return Ok(Some(frame::projector::project(bytes)?));
    }
    Ok(None)
}
