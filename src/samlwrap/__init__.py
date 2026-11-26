"""SAML assertion signature checks."""

from .verify import (
    assertion_batch,
    check_covered,
    check_reference_target,
    check_reference_unique,
    find_signatures,
    parse_document,
    validate_document,
    verify_signature,
)

__all__ = [
    "assertion_batch",
    "check_covered",
    "check_reference_target",
    "check_reference_unique",
    "find_signatures",
    "parse_document",
    "validate_document",
    "verify_signature",
]