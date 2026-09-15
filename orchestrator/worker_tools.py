"""Internal tools: registered for policy checks, never exposed to the voice model."""


def declaration(name, properties):
    return {"name": name, "description": "Trusted task-center worker action.",
            "parameters": {"type": "OBJECT", "properties": properties,
                           "required": list(properties)}}


INTERNAL_TOOL_DECLARATIONS = (
    declaration("coding_prepare", {
        "session_id": {"type": "STRING"}, "plan_hash": {"type": "STRING"},
        "workspace": {"type": "STRING"},
    }),
    declaration("coding_apply", {
        "session_id": {"type": "STRING"}, "diff_hash": {"type": "STRING"},
        "workspace": {"type": "STRING"},
    }),
    declaration("coding_restore", {
        "session_id": {"type": "STRING"}, "diff_hash": {"type": "STRING"},
        "workspace": {"type": "STRING"},
    }),
    declaration("coding_command", {
        "workspace": {"type": "STRING"},
        "argv": {"type": "ARRAY", "items": {"type": "STRING"}},
        "purpose": {"type": "STRING"},
        "timeout_seconds": {"type": "INTEGER"},
    }),
    declaration("coding_inspect", {
        "session_id": {"type": "STRING"}, "workspace": {"type": "STRING"},
        "plan_hash": {"type": "STRING"}, "mode": {"type": "STRING"},
        "image_sha256": {"type": "STRING"},
    }),
    declaration("browser_action", {
        "session_id": {"type": "STRING"}, "action": {"type": "OBJECT"},
        "before_sha256": {"type": "STRING"}, "url": {"type": "STRING"},
    }),
)
INTERNAL_TOOL_NAMES = frozenset(item["name"] for item in INTERNAL_TOOL_DECLARATIONS)
