use calyx_sextant::QueryFilters;

use crate::error::{CliError, CliResult};

pub fn parse(raw: Option<&str>) -> CliResult<QueryFilters> {
    let filters = match raw {
        Some(value) => serde_json::from_str::<QueryFilters>(value)
            .map_err(|err| CliError::usage(format!("parse --filter JSON: {err}")))?,
        None => QueryFilters::default(),
    };
    filters.validate()?;
    Ok(filters)
}
