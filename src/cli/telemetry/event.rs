use serde::Serialize;
use serde_json::Value;

use crackproof_unpacker::{Operation, Stage};

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EventRecord {
    pub(crate) schema: &'static str,
    pub(crate) seq: u64,
    pub(crate) elapsed_ms: u128,
    pub(crate) level: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) stage: Option<Stage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) operation: Option<Operation>,
    pub(crate) kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
    pub(crate) data: Value,
}

impl EventRecord {
    pub(crate) const SCHEMA: &'static str = "crackproof-event/v1";

    pub(crate) fn flush_boundary(&self) -> bool {
        self.kind == "progress"
            || self.kind.ends_with("_started")
            || self.kind.ends_with("_completed")
            || self.kind == "run_failed"
            || matches!(self.level, "warn" | "error")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_event_has_stable_schema() {
        let event = EventRecord {
            schema: EventRecord::SCHEMA,
            seq: 7,
            elapsed_ms: 12,
            level: "info",
            stage: Some(Stage::PayloadRecovery),
            operation: Some(Operation::MaterializeImage),
            kind: "progress",
            message: Some("recovering".to_owned()),
            data: json!({"completed": 2, "total": 4, "unit": "records"}),
        };

        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["schema"], "crackproof-event/v1");
        assert_eq!(value["seq"], 7);
        assert_eq!(value["stage"], "payload_recovery");
        assert_eq!(value["operation"], "materialize_image");
    }
}
