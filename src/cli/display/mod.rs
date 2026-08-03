use std::io;

use super::telemetry::event::EventRecord;

pub(crate) mod interactive;
pub(crate) mod silent;

pub(crate) trait Renderer: Send {
    fn render(&mut self, event: &EventRecord) -> io::Result<()>;

    fn restore(&mut self) -> io::Result<()> {
        Ok(())
    }
}
