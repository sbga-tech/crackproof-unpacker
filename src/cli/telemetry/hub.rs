use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::Value;

use crackproof_unpacker::{Operation, Stage};

use crate::cli::display::Renderer;

use super::event::EventRecord;

pub(crate) type SharedHub = Arc<Mutex<TelemetryHub>>;

pub(crate) struct EventPayload {
    message: Option<String>,
    data: Value,
}

impl EventPayload {
    pub(crate) const fn new(message: Option<String>, data: Value) -> Self {
        Self { message, data }
    }
}

pub(crate) struct TelemetryHub {
    renderer: Box<dyn Renderer>,
    started: Instant,
    next_sequence: u64,
    pub(crate) current_stage: Option<Stage>,
    pub(crate) current_operation: Option<Operation>,
}

impl TelemetryHub {
    pub(crate) fn shared(renderer: Box<dyn Renderer>) -> SharedHub {
        Arc::new(Mutex::new(Self {
            renderer,
            started: Instant::now(),
            next_sequence: 1,
            current_stage: None,
            current_operation: None,
        }))
    }

    pub(crate) fn emit(
        &mut self,
        level: &'static str,
        stage: Option<Stage>,
        operation: Option<Operation>,
        kind: &'static str,
        payload: EventPayload,
    ) -> io::Result<()> {
        let record = self.record(level, stage, operation, kind, payload)?;
        self.renderer.render(&record)
    }

    pub(crate) fn emit_log(
        &mut self,
        level: &'static str,
        message: String,
        data: Value,
    ) -> io::Result<()> {
        self.emit(
            level,
            self.current_stage,
            self.current_operation,
            "log",
            EventPayload::new(Some(message), data),
        )
    }

    fn record(
        &mut self,
        level: &'static str,
        stage: Option<Stage>,
        operation: Option<Operation>,
        kind: &'static str,
        payload: EventPayload,
    ) -> io::Result<EventRecord> {
        let EventPayload { message, data } = payload;
        let seq = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("telemetry sequence overflow"))?;
        Ok(EventRecord {
            schema: EventRecord::SCHEMA,
            seq,
            elapsed_ms: self.started.elapsed().as_millis(),
            level,
            stage,
            operation,
            kind,
            message,
            data,
        })
    }
}

impl Drop for TelemetryHub {
    fn drop(&mut self) {
        let _ = self.renderer.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_sequence_is_strictly_monotonic() {
        let mut hub = TelemetryHub {
            renderer: Box::new(crate::cli::display::silent::SilentRenderer::new()),
            started: Instant::now(),
            next_sequence: 1,
            current_stage: None,
            current_operation: None,
        };
        let first = hub
            .record(
                "info",
                None,
                None,
                "run_started",
                EventPayload::new(None, Value::Null),
            )
            .unwrap();
        let second = hub
            .record(
                "info",
                None,
                None,
                "run_completed",
                EventPayload::new(None, Value::Null),
            )
            .unwrap();
        assert_eq!((first.seq, second.seq), (1, 2));
    }
}
