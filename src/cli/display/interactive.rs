use std::io::{self, Write};

use indicatif::ProgressStyle;
use tracing::Span;
use tracing_indicatif::span_ext::IndicatifSpanExt;
use tracing_indicatif::suspend_tracing_indicatif;

use crackproof_unpacker::{Observer, ProgressUnit, Stage, StateEvent};

use crate::cli::telemetry::observer::{completion_summary, failure_summary};

pub(crate) struct InteractiveObserver {
    input: String,
    spinner_style: ProgressStyle,
    count_style: ProgressStyle,
    bytes_style: ProgressStyle,
}

impl InteractiveObserver {
    pub(crate) fn new(input: String) -> Self {
        let color = std::env::var_os("NO_COLOR").is_none();
        let spinner_template = if color {
            "{spinner:.cyan} [{elapsed_precise}] {wide_msg}"
        } else {
            "{spinner} [{elapsed_precise}] {wide_msg}"
        };
        let count_template = if color {
            "{spinner:.cyan} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {human_pos}/{human_len} {wide_msg}"
        } else {
            "{spinner} [{elapsed_precise}] [{wide_bar}] {human_pos}/{human_len} {wide_msg}"
        };
        let bytes_template = if color {
            "{spinner:.cyan} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} {wide_msg}"
        } else {
            "{spinner} [{elapsed_precise}] [{wide_bar}] {bytes}/{total_bytes} {wide_msg}"
        };
        Self {
            input,
            spinner_style: ProgressStyle::with_template(spinner_template)
                .expect("static spinner template is valid"),
            count_style: ProgressStyle::with_template(count_template)
                .expect("static count template is valid")
                .progress_chars("=>-"),
            bytes_style: ProgressStyle::with_template(bytes_template)
                .expect("static byte template is valid")
                .progress_chars("=>-"),
        }
    }

    fn progress_style(&self, unit: ProgressUnit) -> &ProgressStyle {
        match unit {
            ProgressUnit::Bytes => &self.bytes_style,
            _ => &self.count_style,
        }
    }

    fn message(stage: Stage, operation: crackproof_unpacker::Operation) -> String {
        format!(
            "[{}/{}] {} — {}",
            stage.ordinal(),
            Stage::COUNT,
            stage.title(),
            operation.title()
        )
    }

    fn print_summary(summary: &str) -> io::Result<()> {
        suspend_tracing_indicatif(|| {
            let mut stderr = io::stderr().lock();
            writeln!(stderr, "{summary}")?;
            stderr.flush()
        })
    }
}

impl Observer for InteractiveObserver {
    fn observe(&mut self, event: StateEvent<'_>) -> io::Result<()> {
        match event {
            StateEvent::OperationStarted {
                stage,
                operation,
                total,
                unit,
            } => {
                let span = Span::current();
                span.pb_set_style(total.map_or(&self.spinner_style, |_| self.progress_style(unit)));
                if let Some(total) = total {
                    span.pb_set_length(total);
                }
                span.pb_set_message(&Self::message(stage, operation));
                span.pb_start();
                Ok(())
            }
            StateEvent::Progress {
                stage,
                operation,
                completed,
                total,
                unit,
            } => {
                let span = Span::current();
                span.pb_set_style(self.progress_style(unit));
                span.pb_set_length(total);
                span.pb_set_position(completed);
                span.pb_set_message(&Self::message(stage, operation));
                Ok(())
            }
            StateEvent::StageCompleted { stage, .. } => {
                Span::current().pb_set_finish_message(&format!("completed {}", stage.title()));
                Ok(())
            }
            StateEvent::RunCompleted { summary } => {
                Self::print_summary(&completion_summary(summary))
            }
            StateEvent::RunFailed { failure } => {
                Self::print_summary(&failure_summary(failure, &self.input))
            }
            StateEvent::RunStarted
            | StateEvent::StageStarted { .. }
            | StateEvent::OperationCompleted { .. } => Ok(()),
        }
    }
}
