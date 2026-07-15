use serde_json::Value;

pub(crate) fn public_json_shape(value: &Value) -> (Option<String>, Vec<String>) {
    match value {
        Value::Object(map) => {
            let event_type = if let (Some(topic), Some(kind)) = (
                map.get("topic").and_then(Value::as_str),
                map.get("type").and_then(Value::as_str),
            ) {
                Some(format!("{topic}:{kind}"))
            } else if sports_result_shape(map) {
                Some("sport_result".to_string())
            } else if map.contains_key("statusCode") {
                Some("rtds_error".to_string())
            } else {
                None
            };
            (event_type, map.keys().cloned().collect())
        }
        Value::Array(items) => items
            .first()
            .and_then(Value::as_object)
            .map(|map| (None, map.keys().cloned().collect()))
            .unwrap_or((None, Vec::new())),
        _ => (None, Vec::new()),
    }
}

fn sports_result_shape(map: &serde_json::Map<String, Value>) -> bool {
    if map.contains_key("gameId") || map.contains_key("slug") {
        return true;
    }
    if !map.contains_key("metadataGameId") {
        return false;
    }
    let state_fields = [
        "leagueAbbreviation",
        "homeTeam",
        "awayTeam",
        "status",
        "score",
        "period",
        "elapsed",
        "live",
        "ended",
        "finishedTimestamp",
        "finished_timestamp",
        "eventState",
        "turn",
        "last_update",
    ];
    state_fields
        .iter()
        .filter(|field| map.contains_key(**field))
        .count()
        >= 2
}

