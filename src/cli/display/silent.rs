use std::io::{self, BufWriter, Stdout, Write};

use super::Renderer;
use crate::cli::telemetry::event::EventRecord;

pub(crate) struct SilentRenderer {
    writer: BufWriter<Stdout>,
}

impl SilentRenderer {
    pub(crate) fn new() -> Self {
        Self {
            writer: BufWriter::new(io::stdout()),
        }
    }
}

impl Renderer for SilentRenderer {
    fn render(&mut self, event: &EventRecord) -> io::Result<()> {
        if event.kind != "run_failed" {
            return Ok(());
        }
        serde_json::to_writer(&mut self.writer, event).map_err(io::Error::other)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }
}
