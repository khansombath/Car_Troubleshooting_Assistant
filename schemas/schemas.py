# Define the schema for a single Fact object
fact_schema = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "pattern": "^[a-z0-9_]+$"},
        "description": {"type": "string"},
        "value": {"type": "boolean"},
        "tags": {"type": "array", "items": {"type": "string"}}
    },
    "required": ["id", "description", "value", "tags"]
}

# Define the schema for the array of Facts
facts_array_schema = {
    "type": "array",
    "items": fact_schema
}

# Define the schema for a single Rule object
rule_schema = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "pattern": "^[rR][0-9]+$"},
        "conditions": {"type": "array", "items": {"type": "string"}},
        "conclusion": {"type": "string", "pattern": "^[a-z0-9_]+$"},
        "certainty": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "explain": {"type": "string"}
    },
    "required": ["id", "conditions", "conclusion", "certainty", "explain"]
}

# Define the schema for the array of Rules
rules_array_schema = {
    "type": "array",
    "items": rule_schema
}