from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4

class EventType(str, Enum):
    SECRET_ACCESS = "SECRET_ACCESS"
    NETWORK_CONNECT = "NETWORK_CONNECT"
    NETWORK_SEND = "NETWORK_SEND"

@dataclass(frozen=True)
class SecurityEvent:
    event_type: EventType
    request_id: str = ""
    resource: str = ""
    destination: str = ""
    data_classification: str = "PUBLIC"
    security_context: dict = field(default_factory=dict)
    operation_id: str = field(default_factory=lambda: str(uuid4()))
