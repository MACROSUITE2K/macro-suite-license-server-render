"""Backward-compatible exports for token/license helpers.

New code should import from `server.auth.token_manager`.
"""

from .auth.token_manager import (  # noqa: F401
    TokenError,
    build_activation_token,
    build_launch_token,
    decode_activation_token,
    decode_launch_token,
    generate_license_key,
    hash_license_key,
    is_license_key_format_valid,
    normalize_license_key,
)
