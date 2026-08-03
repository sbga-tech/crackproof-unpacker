use std::io::{self, BufWriter, Stdout, Write};

use crate::cli::display::Renderer;

use super::event::EventRecord;

pub(crate) struct JsonlRenderer {
    writer: BufWriter<Stdout>,
}

impl JsonlRenderer {
    pub(crate) fn new() -> Self {
        Self {
            writer: BufWriter::new(io::stdout()),
        }
    }
}

impl Renderer for JsonlRenderer {
    fn render(&mut self, event: &EventRecord) -> io::Result<()> {
        serde_json::to_writer(&mut self.writer, event).map_err(io::Error::other)?;
        self.writer.write_all(b"\n")?;
        if event.flush_boundary() {
            self.writer.flush()?;
        }
        Ok(())
    }

    fn restore(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
