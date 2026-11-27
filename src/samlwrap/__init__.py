"""SAML assertion signature checks."""

from .verify import (
    assertion_batch,
    assertion_id_used,
    check_audience,
    check_covered,
    check_assertion_binding,
    check_reference_target,
    check_reference_unique,
    check_signature_binding,
    consume_assertion_id,
    find_signatures,
    parse_document,
    reset_seen_assertions,
    validate_document,
    verify_assertion,
    verify_signature,
)

__all__ = [
    "assertion_batch",
    "assertion_id_used",
    "check_audience",
    "check_covered",
    "check_assertion_binding",
    "check_reference_target",
    "check_reference_unique",
    "check_signature_binding",
    "consume_assertion_id",
    "find_signatures",
    "parse_document",
    "reset_seen_assertions",
    "validate_document",
    "verify_assertion",
    "verify_signature",
]
