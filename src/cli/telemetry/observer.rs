use std::io;

use serde_json::{Value, json};

use crackproof_unpacker::{Observer, RunFailure, RunSummary, StateEvent};

use super::hub::{EventPayload, SharedHub};

pub(crate) struct ObserverAdapter {
    hub: SharedHub,
}

impl ObserverAdapter {
    pub(crate) fn new(hub: SharedHub) -> Self {
        Self { hub }
    }
}

impl Observer for ObserverAdapter {
    fn observe(&mut self, event: StateEvent<'_>) -> io::Result<()> {
        let mut hub = self
            .hub
            .lock()
            .map_err(|_| io::Error::other("telemetry hub lock poisoned"))?;
        match event {
            StateEvent::RunStarted => hub.emit(
                "info",
                None,
                None,
                "run_started",
                EventPayload::new(None, json!({"status": "running"})),
            ),
            StateEvent::StageStarted { stage } => {
                hub.current_stage = Some(stage);
                hub.current_operation = None;
                hub.emit(
                    "info",
                    Some(stage),
                    None,
                    "stage_started",
                    EventPayload::new(
                        Some(stage.title().to_owned()),
                        json!({"ordinal": stage.ordinal(), "total": crackproof_unpacker::Stage::COUNT}),
                    ),
                )
            }
            StateEvent::OperationStarted {
                stage,
                operation,
                total,
                unit,
            } => {
                hub.current_stage = Some(stage);
                hub.current_operation = Some(operation);
                hub.emit(
                    "info",
                    Some(stage),
                    Some(operation),
                    "operation_started",
                    EventPayload::new(
                        Some(operation.title().to_owned()),
                        json!({"total": total, "unit": unit}),
                    ),
                )
            }
            StateEvent::Progress {
                stage,
                operation,
                completed,
                total,
                unit,
            } => hub.emit(
                "info",
                Some(stage),
                Some(operation),
                "progress",
                EventPayload::new(
                    Some(format!("{} {completed}/{total}", operation.title())),
                    json!({"completed": completed, "total": total, "unit": unit}),
                ),
            ),
            StateEvent::OperationCompleted { stage, operation } => hub.emit(
                "info",
                Some(stage),
                Some(operation),
                "operation_completed",
                EventPayload::new(None, json!({"status": "complete"})),
            ),
            StateEvent::StageCompleted { stage, duration } => {
                hub.current_operation = None;
                hub.emit(
                    "info",
                    Some(stage),
                    None,
                    "stage_completed",
                    EventPayload::new(None, json!({"elapsed_ms": duration.as_millis()})),
                )
            }
            StateEvent::RunCompleted { summary } => {
                hub.current_stage = None;
                hub.current_operation = None;
                hub.emit(
                    "info",
                    None,
                    None,
                    "run_completed",
                    EventPayload::new(None, json!({"status": "completed", "summary": summary})),
                )
            }
            StateEvent::RunFailed { failure } => {
                hub.current_stage = failure.stage;
                hub.current_operation = failure.operation;
                hub.emit(
                    "error",
                    failure.stage,
                    failure.operation,
                    "run_failed",
                    EventPayload::new(Some(failure.message.clone()), failure_data(failure)),
                )
            }
        }
    }
}

pub(crate) fn completion_summary(summary: &RunSummary) -> String {
    let mut lines = vec![format!(
        "Completed in {:.2}s",
        summary.elapsed_ms as f64 / 1000.0
    )];
    if let Some(input) = &summary.input_artifact {
        let profile = summary.input_pe.as_ref().map_or_else(
            || "PE".to_owned(),
            |pe| format!("{} {}", pe.kind, pe.machine),
        );
        lines.push(format!(
            "Input  {}  {profile}  {} bytes",
            input.path, input.size
        ));
    }
    if let Some(output) = &summary.output_artifact {
        if output.written {
            lines.push(format!(
                "Output {}  {} bytes",
                output.path.as_deref().unwrap_or("<unknown>"),
                output.size
            ));
        } else {
            lines.push(format!(
                "Output verified in memory  {} bytes  not written",
                output.size
            ));
        }
    }
    if let Some(imports) = &summary.imports {
        lines.push(format!(
            "Imports {} modules  {} functions",
            imports.module_count, imports.function_count
        ));
    }
    lines.join("\n")
}

pub(crate) fn failure_summary(failure: &RunFailure, input: &str) -> String {
    let elapsed = failure.partial_summary.elapsed_ms as f64 / 1000.0;
    let mut lines = vec![
        format!("Failed after {elapsed:.2}s"),
        format!("Input  {input}"),
    ];
    if let Some(stage) = failure.stage {
        let operation = failure
            .operation
            .map(|operation| format!(" / {operation}"))
            .unwrap_or_default();
        lines.push(format!("Stage  {stage}{operation}"));
    }
    lines.push(format!("Reason {:?}: {}", failure.reason, failure.message));
    for cause in &failure.causes {
        lines.push(format!("  caused by: {cause}"));
    }
    lines.push(format!("Output preserved: {}", failure.output_preserved));
    lines.join("\n")
}

fn failure_data(failure: &RunFailure) -> Value {
    json!({
        "status": "failed",
        "reason": failure.reason,
        "message": failure.message,
        "causes": failure.causes,
        "output_preserved": failure.output_preserved,
        "partial_summary": failure.partial_summary,
    })
}
