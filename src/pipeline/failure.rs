use std::fmt;

use anyhow::Error;
use serde::Serialize;

use super::outcome::RunSummary;
use super::stage::{Operation, Stage};

/// Stable coarse classification used by the terminal failure event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    InvalidInput,
    Unsupported,
    Ambiguous,
    Io,
    Cancelled,
    Internal,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunFailure {
    pub reason: FailureReason,
    pub stage: Option<Stage>,
    pub operation: Option<Operation>,
    pub message: String,
    pub causes: Vec<String>,
    pub output_preserved: bool,
    pub partial_summary: Box<RunSummary>,
}

pub struct PipelineFailure {
    pub failure: RunFailure,
    source: Error,
}

impl PipelineFailure {
    pub fn new(
        reason: FailureReason,
        stage: Option<Stage>,
        operation: Option<Operation>,
        source: Error,
        partial_summary: RunSummary,
    ) -> Self {
        let message = source.to_string();
        let causes = source.chain().skip(1).map(ToString::to_string).collect();
        Self {
            failure: RunFailure {
                reason,
                stage,
                operation,
                message,
                causes,
                output_preserved: true,
                partial_summary: Box::new(partial_summary),
            },
            source,
        }
    }

    pub fn source_error(&self) -> &Error {
        &self.source
    }
}

impl fmt::Debug for PipelineFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PipelineFailure")
            .field("failure", &self.failure)
            .field("source", &format_args!("{:#}", self.source))
            .finish()
    }
}

impl fmt::Display for PipelineFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.failure.message)
    }
}

impl std::error::Error for PipelineFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}
