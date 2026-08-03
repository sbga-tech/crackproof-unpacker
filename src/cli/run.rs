use std::ffi::OsString;
use std::io::{self, Write};

use clap::Parser;
use serde_json::json;
use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;

use crackproof_unpacker::{
    CancellationToken, FailureReason, Pipeline, PipelineFailure, PipelineOutput, PipelineRequest,
};

use super::args::Args;
use super::display::Renderer;
use super::display::interactive::InteractiveObserver;
use super::display::silent::SilentRenderer;
use super::telemetry::event::EventRecord;
use super::telemetry::hub::{EventPayload, TelemetryHub};
use super::telemetry::jsonl::JsonlRenderer;
use super::telemetry::observer::ObserverAdapter;
use super::telemetry::tracing_layer::HubLayer;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Default,
    Events,
    Silent,
}

pub(crate) fn run() -> i32 {
    let raw = std::env::args_os().collect::<Vec<_>>();
    let args = match Args::try_parse_from(&raw) {
        Ok(args) => args,
        Err(error) => return emit_parse_result(&raw, error),
    };
    let mode = if args.events {
        Mode::Events
    } else if args.silent {
        Mode::Silent
    } else {
        Mode::Default
    };
    match mode {
        Mode::Default => run_interactive(args),
        Mode::Events | Mode::Silent => run_machine(args, mode),
    }
}

fn run_interactive(args: Args) -> i32 {
    let cancellation = CancellationToken::default();
    let signal_token = cancellation.clone();
    if let Err(error) = ctrlc::set_handler(move || signal_token.cancel()) {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "Failed to install Ctrl-C handler: {error}");
        return 1;
    }
    let mut observer = InteractiveObserver::new(args.input.display().to_string());
    let request = PipelineRequest {
        input: args.input,
        output: args.output,
        dry_run: args.dry_run,
        hash_artifacts: false,
    };
    let indicatif_layer = IndicatifLayer::new();
    let log_writer = indicatif_layer.get_stderr_writer();
    let log_layer = tracing_subscriber::fmt::layer()
        .compact()
        .without_time()
        .with_target(false)
        .with_ansi(std::env::var_os("NO_COLOR").is_none())
        .with_writer(log_writer)
        .with_filter(LevelFilter::INFO);
    let subscriber = tracing_subscriber::registry()
        .with(log_layer)
        .with(indicatif_layer);
    let result = tracing::subscriber::with_default(subscriber, || {
        Pipeline::new(&mut observer, &cancellation).run(&request)
    });
    result_exit_code(result)
}

fn run_machine(args: Args, mode: Mode) -> i32 {
    let renderer: Box<dyn Renderer> = match mode {
        Mode::Events => Box::new(JsonlRenderer::new()),
        Mode::Silent => Box::new(SilentRenderer::new()),
        Mode::Default => unreachable!("interactive mode has a dedicated tracing subscriber"),
    };
    let hub = TelemetryHub::shared(renderer);
    let cancellation = CancellationToken::default();
    let signal_token = cancellation.clone();
    if let Err(error) = ctrlc::set_handler(move || signal_token.cancel()) {
        if let Ok(mut hub) = hub.lock() {
            let _ = hub.emit(
                "error",
                None,
                None,
                "run_failed",
                EventPayload::new(
                    Some(error.to_string()),
                    json!({
                        "status": "failed",
                        "reason": "internal",
                        "message": error.to_string(),
                        "causes": [],
                        "output_preserved": true
                    }),
                ),
            );
        }
        return 1;
    }
    let mut observer = ObserverAdapter::new(hub.clone());
    let request = PipelineRequest {
        input: args.input,
        output: args.output,
        dry_run: args.dry_run,
        hash_artifacts: mode == Mode::Events,
    };
    let tracing_level = match mode {
        Mode::Events => LevelFilter::TRACE,
        Mode::Silent => LevelFilter::OFF,
        Mode::Default => unreachable!("interactive mode has a dedicated tracing subscriber"),
    };
    let subscriber =
        tracing_subscriber::registry().with(HubLayer::new(hub).with_filter(tracing_level));
    let result = tracing::subscriber::with_default(subscriber, || {
        Pipeline::new(&mut observer, &cancellation).run(&request)
    });
    result_exit_code(result)
}

fn result_exit_code(result: Result<PipelineOutput, PipelineFailure>) -> i32 {
    match result {
        Ok(_) => 0,
        Err(failure) if failure.failure.reason == FailureReason::Cancelled => 130,
        Err(failure) if failure.failure.reason == FailureReason::InvalidInput => 2,
        Err(_) => 1,
    }
}

fn emit_parse_result(raw: &[OsString], error: clap::Error) -> i32 {
    if !Args::machine_mode_requested(raw) {
        let code = error.exit_code();
        let _ = error.print();
        return code;
    }
    if matches!(
        error.kind(),
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
    ) {
        let mut stdout = io::stdout().lock();
        let _ = write!(stdout, "{error}");
        return 0;
    }
    let record = EventRecord {
        schema: EventRecord::SCHEMA,
        seq: 1,
        elapsed_ms: 0,
        level: "error",
        stage: None,
        operation: None,
        kind: "run_failed",
        message: Some(error.to_string()),
        data: json!({
            "status": "failed",
            "reason": "invalid_input",
            "message": error.to_string(),
            "causes": [],
            "output_preserved": true
        }),
    };
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &record).is_ok() {
        let _ = stdout.write_all(b"\n");
        let _ = stdout.flush();
    }
    2
}
