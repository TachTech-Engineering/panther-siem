import json

from panther_base_helpers import deep_get
from panther_okta_helpers import okta_alert_context


def rule(event):
    if event.get("eventtype") != "policy.evaluate_sign_on":
        return False

    behaviors = event.deep_get("debugContext", "debugData", "behaviors")
    if behaviors:
        return "New Device=POSITIVE" in behaviors

    log_only_security_data = event.deep_get("debugContext", "debugData", "logOnlySecurityData")
    if isinstance(log_only_security_data, str):
        log_only_security_data = json.loads(log_only_security_data)
    return (
        deep_get(log_only_security_data, "behaviors", "New Device") == "POSITIVE"
    )


def title(event):
    return (
        f"{event.deep_get('actor', 'displayName', default='<displayName-not-found>')} "
        f"<{event.deep_get('actor', 'alternateId', default='alternateId-not-found')}> "
        f"accessed Okta Admin Console using new behaviors: "
        f"New Device: {event.deep_get('device', 'name', default='<deviceName-not-found>')}"
    )


def alert_context(event):
    return okta_alert_context(event)
