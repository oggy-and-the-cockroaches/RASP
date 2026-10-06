import ctypes
from pathlib import Path
from .events import SecurityEvent

class NativeEngine:
    def __init__(self, policy):
        library = Path(__file__).with_name("_native") / "sentinel_core.dll"
        if not library.exists():
            from .build_native import build
            build(library)
        self._lib = ctypes.CDLL(str(library))
        self._lib.sentinel_evaluate.argtypes = [ctypes.c_char_p] * 7 + [ctypes.c_char_p, ctypes.c_uint]
        self._lib.sentinel_evaluate.restype = ctypes.c_int
        self.policy = policy
    def evaluate(self, event: SecurityEvent):
        reason = ctypes.create_string_buffer(128)
        args = [self.policy.name, event.event_type.value, event.request_id, event.resource,
                event.destination, event.data_classification, event.operation_id]
        blocked = self._lib.sentinel_evaluate(*[x.encode() for x in args], reason, len(reason))
        return ("BLOCK" if blocked else "ALLOW", reason.value.decode())
