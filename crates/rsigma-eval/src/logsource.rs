//! Event logsource extraction for opt-in, conflict-based logsource pruning.
//!
//! A [`LogSourceExtractor`] derives a [`LogSource`] from an event. The built-in
//! [`FieldLogSourceExtractor`] reads configurable field names (defaulting to
//! the literals `product`, `service`, and `category`), falling back to optional
//! static defaults. The result feeds the engine's conflict-based pruning: an
//! event tagged `product: windows` skips `product: linux` rules without
//! dropping Windows-category or logsource-less rules.
//!
//! Extraction is fail-open per dimension: a field that is absent, null, or
//! blank leaves that dimension unset (after the static default is consulted),
//! so a missing tag never prunes anything. Custom extractors are expected to
//! preserve that contract — returning [`LogSource::default()`] rather than
//! guessing keeps pruning safe.

use rsigma_parser::LogSource;

use crate::event::Event;

/// Derives an event [`LogSource`] for conflict-based pruning on the evaluation
/// hot path.
///
/// Implementors are installed on an engine via
/// [`Engine::set_logsource_extractor`] as an `Arc<dyn LogSourceExtractor>`;
/// see [`FieldLogSourceExtractor`] for the built-in field-reading
/// implementation.
///
/// [`Engine::set_logsource_extractor`]: crate::Engine::set_logsource_extractor
pub trait LogSourceExtractor: Send + Sync {
    /// Extract the event's logsource. Each dimension left unset is a wildcard
    /// for pruning, so an extractor that cannot determine a dimension must
    /// leave it `None` rather than guess (fail-open).
    fn extract(&self, event: &dyn Event) -> LogSource;

    /// Resolve one dimension from an event field: the trimmed, non-blank field
    /// value wins, then `default`, then unset.
    ///
    /// The default body implements the fail-open contract every dimension
    /// follows; implementors override it only to change how a single field is
    /// read.
    fn resolve(&self, event: &dyn Event, field: &str, default: Option<&str>) -> Option<String> {
        if let Some(value) = event.get_field(field)
            && let Some(s) = value.as_str()
        {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        default.map(str::to_string)
    }
}

/// A [`LogSourceExtractor`] that reads configurable event fields plus static
/// defaults.
///
/// Each dimension is resolved independently in precedence order: the value of
/// the configured event field, then the static default, then unset (`None`).
/// A present-but-blank field value is treated as unset.
///
/// # Example
///
/// ```rust
/// use rsigma_eval::{FieldLogSourceExtractor, LogSourceExtractor};
/// use rsigma_eval::event::JsonEvent;
/// use serde_json::json;
///
/// let extractor = FieldLogSourceExtractor::new();
/// let ev = json!({"product": "windows"});
/// let event = JsonEvent::borrow(&ev);
///
/// let ls = extractor.extract(&event);
/// assert_eq!(ls.product.as_deref(), Some("windows"));
/// assert_eq!(ls.category, None); // absent fields stay unset (fail-open)
/// ```
#[derive(Debug, Clone)]
pub struct FieldLogSourceExtractor {
    product_field: String,
    service_field: String,
    category_field: String,
    /// Extra dimensions: `(logsource custom key, event field name)`. Each
    /// resolves into [`LogSource::custom`] for conflict-based pruning beyond
    /// the standard three dimensions.
    custom_fields: Vec<(String, String)>,
    defaults: LogSource,
}

impl FieldLogSourceExtractor {
    /// Create an extractor that reads the literal `product`, `service`, and
    /// `category` fields with no static defaults.
    pub fn new() -> Self {
        FieldLogSourceExtractor {
            product_field: "product".to_string(),
            service_field: "service".to_string(),
            category_field: "category".to_string(),
            custom_fields: Vec::new(),
            defaults: LogSource::default(),
        }
    }

    /// Override the event field names read for each dimension.
    #[must_use]
    pub fn with_field_names(
        mut self,
        product_field: impl Into<String>,
        service_field: impl Into<String>,
        category_field: impl Into<String>,
    ) -> Self {
        self.product_field = product_field.into();
        self.service_field = service_field.into();
        self.category_field = category_field.into();
        self
    }

    /// Set the extra `(custom dimension, event field)` mappings read into
    /// [`LogSource::custom`]. Each pair reads the event field and stores it
    /// under the custom dimension key; absent fields fall back to the static
    /// custom default (if any) and are otherwise omitted (fail-open).
    #[must_use]
    pub fn with_custom_fields(mut self, custom_fields: Vec<(String, String)>) -> Self {
        self.custom_fields = custom_fields;
        self
    }

    /// Set the static per-dimension defaults applied when a field is absent.
    /// `product`, `service`, `category`, and the `custom` map are consulted.
    #[must_use]
    pub fn with_defaults(mut self, defaults: LogSource) -> Self {
        self.defaults = defaults;
        self
    }
}

impl LogSourceExtractor for FieldLogSourceExtractor {
    /// Extract the event's logsource. Each dimension resolves to the configured
    /// field value, then the static default, then `None`/absent (fail-open).
    fn extract(&self, event: &dyn Event) -> LogSource {
        // Start from the static custom defaults, then let event-field values
        // win per key.
        let mut custom = self.defaults.custom.clone();
        for (dimension, field) in &self.custom_fields {
            if let Some(value) = self.resolve(event, field, None) {
                custom.insert(dimension.clone(), value);
            }
        }
        LogSource {
            product: self.resolve(event, &self.product_field, self.defaults.product.as_deref()),
            service: self.resolve(event, &self.service_field, self.defaults.service.as_deref()),
            category: self.resolve(
                event,
                &self.category_field,
                self.defaults.category.as_deref(),
            ),
            custom,
            ..LogSource::default()
        }
    }
}

impl Default for FieldLogSourceExtractor {
    fn default() -> Self {
        Self::new()
    }
}
