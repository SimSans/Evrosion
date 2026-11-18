//! Root's read-only chooser uses an authoritative directory inspection before
//! List. Revision0 is a value, never an undocumented wildcard.
use ev_userspace_contract::workspace::{EntryState, Kind, ObjectId, Operation, Outcome, Response};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query {
    pub operation: Operation,
    pub cursor: u16,
    pub revision: u64,
    pub changed: bool,
}
pub fn after_inspect(
    directory: ObjectId,
    cursor: u16,
    previous: Option<u64>,
    response: Response,
) -> Option<Query> {
    let entry = response.entry?;
    if response.outcome != Outcome::Completed
        || entry.object != directory
        || entry.kind != Kind::Directory
        || entry.state != EntryState::Live
    {
        return None;
    }
    let changed = previous.is_some_and(|revision| revision != response.namespace_revision);
    let cursor = if changed { 0 } else { cursor };
    Some(Query {
        cursor,
        revision: response.namespace_revision,
        changed,
        operation: Operation::List {
            directory,
            cursor,
            expected_namespace_revision: response.namespace_revision,
        },
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::workspace::{DatasetId, Entry, Name};
    #[test]
    fn list_uses_actual_inspection_revision_and_changed_namespace_resets_cursor() {
        let dir = ObjectId {
            slot: 0,
            generation: 1,
        };
        let response = Response {
            request_id: 1,
            operation_id: 0,
            outcome: Outcome::Completed,
            namespace_revision: 3,
            dataset: DatasetId([1; 16]),
            next_cursor: None,
            entry: Some(Entry {
                object: dir,
                parent: dir,
                revision: 1,
                size: 0,
                kind: Kind::Directory,
                state: EntryState::Live,
                name: Name::root(),
            }),
        };
        let first = after_inspect(dir, 0, None, response).unwrap();
        assert_eq!(
            first.operation,
            Operation::List {
                directory: dir,
                cursor: 0,
                expected_namespace_revision: 3
            }
        );
        assert!(!first.changed);
        assert_eq!(after_inspect(dir, 8, Some(3), response).unwrap().cursor, 8);
        let reset = after_inspect(dir, 8, Some(2), response).unwrap();
        assert!(reset.changed);
        assert_eq!(reset.cursor, 0);
        assert!(
            after_inspect(
                dir,
                0,
                None,
                Response {
                    outcome: Outcome::Conflict,
                    ..response
                }
            )
            .is_none()
        );
        assert!(
            after_inspect(
                ObjectId {
                    slot: 1,
                    generation: 1
                },
                0,
                None,
                response
            )
            .is_none()
        );
    }
}
