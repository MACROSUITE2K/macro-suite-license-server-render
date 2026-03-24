import math
import string
from typing import Mapping


DEFAULT_MARKERS = (
    "change-this",
    "replace-with",
    "changeme",
    "your-secret",
    "default",
    "example",
    "password",
    "token",
)


class SecretValidationError(RuntimeError):
    """Raised when security-critical secrets are weak or default."""


def _shannon_entropy_per_char(value: str) -> float:
    if not value:
        return 0.0

    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1

    entropy = 0.0
    length = len(value)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _character_class_count(value: str) -> int:
    classes = 0
    if any(c in string.ascii_lowercase for c in value):
        classes += 1
    if any(c in string.ascii_uppercase for c in value):
        classes += 1
    if any(c in string.digits for c in value):
        classes += 1
    if any(c in string.punctuation for c in value):
        classes += 1
    return classes


def validate_server_secrets(
    secret_map: Mapping[str, str],
    *,
    min_length: int = 32,
    min_entropy_bits: float = 128.0,
) -> None:
    errors: list[str] = []

    for name, raw_value in secret_map.items():
        value = str(raw_value or "").strip()
        lowered = value.lower()

        if not value:
            errors.append(f"{name}: value is empty")
            continue

        if len(value) < min_length:
            errors.append(f"{name}: must be at least {min_length} characters")

        if any(marker in lowered for marker in DEFAULT_MARKERS):
            errors.append(f"{name}: default/placeholder marker detected")

        class_count = _character_class_count(value)
        if class_count < 3:
            errors.append(f"{name}: must include at least 3 character classes")

        entropy_bits = _shannon_entropy_per_char(value) * len(value)
        if entropy_bits < min_entropy_bits:
            errors.append(f"{name}: estimated entropy too low ({entropy_bits:.1f} bits)")

    if errors:
        joined = "\n - ".join(errors)
        raise SecretValidationError(
            "Insecure secret configuration detected. Refusing startup.\n"
            f" - {joined}\n"
            "Generate strong random values in .env before launching."
        )
