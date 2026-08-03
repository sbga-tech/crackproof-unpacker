use std::io;
use std::time::Duration;

use super::failure::RunFailure;
use super::outcome::RunSummary;
use super::progress::ProgressUnit;
use super::stage::{Operation, Stage};

/// Authoritative lifecycle state consumed by presentation adapters.
#[derive(Debug)]
pub enum StateEvent<'a> {
    RunStarted,
    StageStarted {
        stage: Stage,
    },
    OperationStarted {
        stage: Stage,
        operation: Operation,
        total: Option<u64>,
        unit: ProgressUnit,
    },
    Progress {
        stage: Stage,
        operation: Operation,
        completed: u64,
        total: u64,
        unit: ProgressUnit,
    },
    OperationCompleted {
        stage: Stage,
        operation: Operation,
    },
    StageCompleted {
        stage: Stage,
        duration: Duration,
    },
    RunCompleted {
        summary: &'a RunSummary,
    },
    RunFailed {
        failure: &'a RunFailure,
    },
}

/// Receives typed run state. Returning an I/O error aborts the run because the
/// selected machine-output contract can no longer be fulfilled.
pub trait Observer {
    fn observe(&mut self, event: StateEvent<'_>) -> io::Result<()>;
}

#[derive(Debug, Default)]
pub struct NoopObserver;

impl Observer for NoopObserver {
    fn observe(&mut self, _event: StateEvent<'_>) -> io::Result<()> {
        Ok(())
    }
}
