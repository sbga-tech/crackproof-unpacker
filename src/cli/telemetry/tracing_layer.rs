use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::hub::SharedHub;

#[derive(Clone, Debug, Default)]
struct RecordedFields(BTreeMap<String, Value>);

#[derive(Default)]
struct JsonVisitor {
    fields: BTreeMap<String, Value>,
}

impl Visit for JsonVisitor {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.insert(field.name().to_owned(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.insert(field.name().to_owned(), value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields.insert(field.name().to_owned(), value.into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), Value::String(value.to_owned()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.fields
            .insert(field.name().to_owned(), Value::String(format!("{value:?}")));
    }
}

#[derive(Clone)]
pub(crate) struct HubLayer {
    hub: SharedHub,
}

impl HubLayer {
    pub(crate) fn new(hub: SharedHub) -> Self {
        Self { hub }
    }
}

impl<S> Layer<S> for HubLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        context: Context<'_, S>,
    ) {
        let mut visitor = JsonVisitor::default();
        attributes.record(&mut visitor);
        if let Some(span) = context.span(id) {
            span.extensions_mut().insert(RecordedFields(visitor.fields));
        }
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        context: Context<'_, S>,
    ) {
        let mut visitor = JsonVisitor::default();
        values.record(&mut visitor);
        if let Some(span) = context.span(id) {
            let mut extensions = span.extensions_mut();
            if let Some(fields) = extensions.get_mut::<RecordedFields>() {
                fields.0.extend(visitor.fields);
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, context: Context<'_, S>) {
        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);
        let mut fields = BTreeMap::new();
        if let Some(scope) = context.event_scope(event) {
            for span in scope.from_root() {
                if let Some(span_fields) = span.extensions().get::<RecordedFields>() {
                    fields.extend(span_fields.0.clone());
                }
            }
        }
        fields.extend(visitor.fields);
        let message = fields
            .remove("message")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| event.metadata().name().to_owned());
        fields.remove("stage");
        fields.remove("operation");
        let level = match *event.metadata().level() {
            tracing::Level::TRACE => "trace",
            tracing::Level::DEBUG => "debug",
            tracing::Level::INFO => "info",
            tracing::Level::WARN => "warn",
            tracing::Level::ERROR => "error",
        };
        if let Ok(mut hub) = self.hub.lock() {
            let _ = hub.emit_log(level, message, Value::Object(Map::from_iter(fields)));
        }
    }
}
