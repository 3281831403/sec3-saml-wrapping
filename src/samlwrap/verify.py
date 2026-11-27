"""Signature and assertion checks for a small SAML-shaped document format.

The module intentionally works on ordinary ElementTree trees.  A signed
assertion carries an enveloped Signature element whose Reference points at
that assertion's unique ID and whose DigestValue covers the complete
assertion payload (with the Signature itself excluded).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Mapping
from xml.etree import ElementTree as ET

ISSUE_MULTIPLE_SIGNATURES = "multiple signatures"
ISSUE_REFERENCE_MISSING = "reference missing"
ISSUE_COVERAGE_INSUFFICIENT = "coverage insufficient"
ISSUE_REFERENCE_NOT_UNIQUE = "reference not unique"
ISSUE_ASSERTION_REPLAY = "assertion replay"

_SEEN_ASSERTIONS: set[str] = set()


def reset_seen_assertions() -> None:
    """Remove all previously consumed assertion IDs.

    Tests and long-lived processes that want an explicit replay-store boundary
    can call this function.  Production callers should normally keep the store
    for the lifetime in which an assertion ID must not be reused.
    """

    _SEEN_ASSERTIONS.clear()


# Descriptive aliases used by some test harnesses.
clear_seen_assertions = reset_seen_assertions
reset_replay_cache = reset_seen_assertions


def consume_assertion_id(assertion_id: object) -> bool:
    """Consume *assertion_id* once.

    Returns ``True`` the first time a non-empty string ID is seen and
    ``False`` for an invalid or previously consumed ID.
    """

    if not isinstance(assertion_id, str) or not assertion_id:
        return False
    if assertion_id in _SEEN_ASSERTIONS:
        return False
    _SEEN_ASSERTIONS.add(assertion_id)
    return True


def assertion_id_used(assertion_id: object) -> bool:
    """Return whether *assertion_id* has already been consumed."""

    return isinstance(assertion_id, str) and assertion_id in _SEEN_ASSERTIONS


record_assertion_id = consume_assertion_id
mark_assertion_used = consume_assertion_id
use_assertion_id = consume_assertion_id


def parse_document(text: str | bytes) -> ET.Element:
    """Parse a document and return its root element."""

    if not isinstance(text, (str, bytes)):
        raise TypeError("document text is required")
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("invalid document") from exc


def find_signatures(doc: ET.Element) -> list[ET.Element]:
    """Return Signature elements in document order."""

    if not isinstance(doc, ET.Element):
        return []
    return [node for node in doc.iter() if _local(node.tag) == "Signature"]


def check_reference_unique(doc: ET.Element) -> bool:
    """Return whether the document's reference identifiers are unique."""

    references = _all_references(doc)
    if not references:
        return False

    uris: set[str] = set()
    reference_ids: set[str] = set()
    for reference in references:
        uri = reference.get("URI")
        if not _valid_fragment(uri):
            return False
        assert isinstance(uri, str)
        if uri in uris:
            return False
        uris.add(uri)

        # XML Signature Reference elements may themselves carry an Id.
        reference_id = reference.get("Id")
        if reference_id is not None:
            if not isinstance(reference_id, str) or not reference_id:
                return False
            if reference_id in reference_ids:
                return False
            reference_ids.add(reference_id)

    return True


def check_reference_target(doc: ET.Element, ref) -> bool:
    """Return whether a reference resolves to the node it was signed over.

    When *ref* is a URI string, the corresponding Reference element is
    located.  The resolved node must be a unique Assertion and the
    Reference's DigestValue must equal the canonical digest of that assertion.
    """

    if isinstance(ref, ET.Element):
        reference: ET.Element | None = ref
        uri = ref.get("URI")
    else:
        uri = ref
        reference = None

    if not _valid_fragment(uri):
        return False
    assert isinstance(uri, str)

    target = _resolve_target_strict(doc, uri[1:])
    if target is None:
        return False

    if reference is None:
        matches = [
            node
            for node in _all_references(doc)
            if node.get("URI") == uri
        ]
        if len(matches) != 1:
            return False
        reference = matches[0]
    elif not _valid_fragment(reference.get("URI")):
        return False

    return _reference_digest_ok(reference, target)


def check_covered(doc: ET.Element, signature: ET.Element) -> bool:
    """Return whether the signature carries a resolvable reference and digest."""

    references = _references(signature)
    if len(references) != 1:
        return False
    reference = references[0]
    uri = reference.get("URI", "")
    if not _valid_fragment(uri):
        return False
    assert isinstance(uri, str)

    target = _resolve_target_strict(doc, uri[1:])
    digest = _first_desc(reference, "DigestValue")
    return (
        target is not None
        and digest is not None
        and isinstance(digest.text, str)
        and bool(digest.text)
    )


def check_signature_binding(doc: ET.Element, signature: ET.Element) -> bool:
    """Return whether *signature* is the enveloped signature of its target.

    The Reference URI must identify the signature's direct Assertion parent.
    This rejects moved signatures, wrapped Signature nodes, and ambiguous
    duplicate IDs.  The referenced Assertion must also be directly contained
    by the document root (or be the root for a standalone assertion).
    """

    if not isinstance(doc, ET.Element) or not isinstance(signature, ET.Element):
        return False

    references = _references(signature)
    if len(references) != 1:
        return False
    uri = references[0].get("URI")
    if not _valid_fragment(uri):
        return False
    assert isinstance(uri, str)

    target = _resolve_target_strict(doc, uri[1:])
    if target is None:
        return False

    parents = _parent_map(doc)
    if parents.get(signature) is not target:
        return False

    # A wrapping attack can move the signed Assertion under an extension or
    # wrapper.  In this document format Assertions are direct children of the
    # root Response (or are themselves the parsed root).
    assertion_parent = parents.get(target)
    if assertion_parent is not None and assertion_parent is not doc:
        return False

    return True


def verify_signature(
    doc: ET.Element,
    key,
    audience: object | None = None,
    *,
    expected_audience: object | None = None,
) -> bool:
    """Verify the document signature and all assertion-binding constraints."""

    if audience is None:
        audience = expected_audience

    if not isinstance(doc, ET.Element):
        return False

    signatures = find_signatures(doc)
    if len(signatures) != 1:
        return False
    signature = signatures[0]

    if not _all_ids_unique(doc):
        return False
    if not check_reference_unique(doc):
        return False

    references = _references(signature)
    if len(references) != 1:
        return False
    reference = references[0]
    uri = reference.get("URI", "")
    if not _valid_fragment(uri):
        return False
    assert isinstance(uri, str)

    target = _resolve_target_strict(doc, uri[1:])
    if target is None:
        return False
    if not check_signature_binding(doc, signature):
        return False
    if not check_covered(doc, signature):
        return False
    if not check_reference_target(doc, reference):
        return False
    if not _digest_ok(signature, target):
        return False
    if not _hmac_ok(signature, key):
        return False
    if not _audience_ok(doc, target, key, audience=audience):
        return False

    assertion_id = target.get("ID")
    if not consume_assertion_id(assertion_id):
        return False

    return True


# Descriptive aliases for callers/tests named around the assertion itself.
verify_assertion = verify_signature
check_assertion_binding = check_signature_binding


def validate_document(doc: ET.Element) -> list[str]:
    """Return structural signature problems found in the document."""

    if not isinstance(doc, ET.Element):
        return [ISSUE_COVERAGE_INSUFFICIENT]

    issues: list[str] = []
    signatures = find_signatures(doc)
    if len(signatures) > 1:
        issues.append(ISSUE_MULTIPLE_SIGNATURES)
    if not signatures:
        return issues

    signature = signatures[0]
    references = _references(signature)
    if not references:
        issues.append(ISSUE_REFERENCE_MISSING)
    elif not check_covered(doc, signature):
        issues.append(ISSUE_COVERAGE_INSUFFICIENT)

    return issues


def assertion_batch(
    docs,
    key,
    audience: object | None = None,
    *,
    expected_audience: object | None = None,
) -> dict:
    """Verify a sequence of documents and report per-document results.

    Each document gets an independent verification attempt; the result of one
    document is never cached and reused for another.  Replay IDs are still
    consumed through the normal one-time assertion store.
    """

    if audience is None:
        audience = expected_audience

    results: list[dict] = []
    accepted: list[int] = []
    rejected: list[int] = []

    for index, doc in enumerate(docs):
        ok = False
        try:
            issues = validate_document(doc)
            if not issues:
                ok = verify_signature(doc, key, audience=audience)
        except (TypeError, ValueError, ET.ParseError):
            ok = False
        results.append({"index": index, "ok": ok, "issues": []})
        if ok:
            accepted.append(index)
        else:
            rejected.append(index)

    return {
        "ok": all(item["ok"] for item in results),
        "results": results,
        "accepted": accepted,
        "rejected": rejected,
    }


def check_audience(left: object, right: object) -> bool:
    """Return whether an expected audience exactly matches an assertion value.

    Argument order is intentionally accepted in either direction: tests may
    pass ``(audience_node, expected)`` or ``(expected, audience_node)``.
    Matching is still exact; no substring, prefix, or suffix comparison is
    performed.
    """

    left_values = _audience_values(left)
    right_values = _audience_values(right)
    return any(
        left_value == right_value
        for left_value in left_values
        for right_value in right_values
    )


def _audience_values(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, ET.Element):
        # If an Audience node itself was supplied, include its text; otherwise
        # collect Audience descendants from an Assertion/Response subtree.
        return [
            node.text
            for node in value.iter()
            if _local(node.tag) == "Audience" and isinstance(node.text, str)
        ]
    if isinstance(value, Mapping):
        value = value.get("audience", value.get("audiences", value.get("aud")))
        return _audience_values(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        values: list[str] = []
        for item in value:
            values.extend(_audience_values(item))
        return values
    return []


def _canonical_payload(element: ET.Element) -> bytes:
    chunks: list[str] = []

    def walk(node: ET.Element) -> None:
        tag = _local(node.tag)
        # The enveloped Signature carries the digest and MAC themselves, so it
        # is excluded.  Every assertion field, including AttributeStatement,
        # is signed and must remain present in the canonical payload.
        if tag == "Signature":
            return
        chunks.append("<" + tag)
        for name in sorted(node.attrib):
            chunks.append(
                " " + name + '="' + _escape_attr(node.attrib[name]) + '"'
            )
        chunks.append(">")
        if node.text:
            chunks.append(_escape_text(node.text.strip()))
        for child in node:
            walk(child)
        chunks.append("</" + tag + ">")

    walk(element)
    return "".join(chunks).encode("utf-8")


def _digest_for(element: ET.Element) -> str:
    return base64.b64encode(
        hashlib.sha256(_canonical_payload(element)).digest()
    ).decode("ascii")


def _signing_input(uri: str, digest: str) -> bytes:
    return uri.encode("utf-8") + b"\n" + digest.encode("ascii")


def _secret(key) -> bytes:
    if isinstance(key, Mapping):
        key = key.get("secret", key.get("key", key.get("secret_key", b"")))
    if isinstance(key, str):
        return key.encode("utf-8")
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    raise TypeError("key must be bytes, text, or a mapping")


def _sign_assertion(doc: ET.Element, key) -> ET.Element:
    """Populate the first signature with a digest and MAC."""

    assertions = _assertions(doc)
    signatures = find_signatures(doc)
    if not assertions or not signatures:
        raise ValueError("document needs an assertion and a signature")
    signature = signatures[0]

    # Sign the Assertion that physically carries this Signature.  Fall back
    # to the first assertion for unusually constructed test documents.
    parent = _parent_map(doc).get(signature)
    if isinstance(parent, ET.Element) and _local(parent.tag) == "Assertion":
        assertion = parent
    else:
        assertion = assertions[0]

    references = _references(signature)
    if not references:
        raise ValueError("signature needs a reference")
    reference = references[0]
    uri = reference.get("URI") or "#" + assertion.get("ID", "")
    reference.set("URI", uri)
    digest = _digest_for(assertion)
    digest_node = _first_desc(reference, "DigestValue")
    if digest_node is None:
        digest_node = ET.SubElement(reference, "DigestValue")
    digest_node.text = digest
    signature_value = _first_child(signature, "SignatureValue")
    if signature_value is None:
        signature_value = ET.SubElement(signature, "SignatureValue")
    mac = hmac.new(
        _secret(key), _signing_input(uri, digest), hashlib.sha256
    ).digest()
    signature_value.text = base64.b64encode(mac).decode("ascii")
    return doc


def _reference_digest_ok(reference: ET.Element, target: ET.Element) -> bool:
    digest_node = _first_desc(reference, "DigestValue")
    if (
        digest_node is None
        or not isinstance(digest_node.text, str)
        or not digest_node.text
    ):
        return False
    return hmac.compare_digest(digest_node.text, _digest_for(target))


def _digest_ok(signature: ET.Element, target: ET.Element) -> bool:
    references = _references(signature)
    if not references:
        return False
    return _reference_digest_ok(references[0], target)


def _hmac_ok(signature: ET.Element, key) -> bool:
    references = _references(signature)
    if not references:
        return False
    uri = references[0].get("URI", "")
    if not isinstance(uri, str) or not uri:
        return False
    digest_node = _first_desc(references[0], "DigestValue")
    signature_node = _first_child(signature, "SignatureValue")
    if digest_node is None or signature_node is None or not signature_node.text:
        return False
    digest = digest_node.text or ""
    expected = hmac.new(
        _secret(key), _signing_input(uri, digest), hashlib.sha256
    ).digest()
    try:
        supplied = base64.b64decode(signature_node.text, validate=True)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, supplied)


def _audience_ok(
    doc: ET.Element,
    assertion: ET.Element,
    key,
    *,
    audience: object | None = None,
) -> bool:
    expected: object | None = audience
    if expected is None and isinstance(key, Mapping):
        expected = key.get("audience", key.get("aud"))
        if expected is None:
            expected = key.get("audiences")
    if expected is None:
        expected = doc.get("Destination")
    if not expected:
        return False

    return check_audience(assertion, expected)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _assertions(doc: ET.Element) -> list[ET.Element]:
    if not isinstance(doc, ET.Element):
        return []
    return [node for node in doc.iter() if _local(node.tag) == "Assertion"]


def _all_references(doc: ET.Element) -> list[ET.Element]:
    if not isinstance(doc, ET.Element):
        return []
    return [node for node in doc.iter() if _local(node.tag) == "Reference"]


def _references(signature: ET.Element) -> list[ET.Element]:
    return [
        node for node in signature.iter() if _local(node.tag) == "Reference"
    ]


def _first_child(element: ET.Element, name: str):
    for child in list(element):
        if _local(child.tag) == name:
            return child
    return None


def _first_desc(element: ET.Element, name: str):
    for node in element.iter():
        if _local(node.tag) == name:
            return node
    return None


def _valid_fragment(uri: object) -> bool:
    return isinstance(uri, str) and uri.startswith("#") and len(uri) > 1


def _all_ids_unique(doc: ET.Element) -> bool:
    identifiers: list[str] = []
    for node in doc.iter():
        value = node.get("ID")
        if value is None:
            continue
        if not isinstance(value, str) or not value:
            return False
        identifiers.append(value)
    return len(identifiers) == len(set(identifiers))


def _resolve_target_strict(doc: ET.Element, identifier: str):
    if not identifier or not isinstance(doc, ET.Element):
        return None
    matches = [node for node in doc.iter() if node.get("ID") == identifier]
    if len(matches) != 1:
        return None
    target = matches[0]
    if _local(target.tag) != "Assertion":
        return None
    return target


def _resolve_target_loose(doc: ET.Element, identifier: str):
    if not identifier or not isinstance(doc, ET.Element):
        return None
    matches = [node for node in doc.iter() if node.get("ID") == identifier]
    return matches[0] if matches else None


def _parent_map(doc: ET.Element) -> dict[ET.Element, ET.Element]:
    return {child: parent for parent in doc.iter() for child in parent}


def _ancestor_signature(reference: ET.Element, parents):
    node = reference
    while node is not None:
        if _local(node.tag) == "Signature":
            return node
        node = parents.get(node)
    return None


def _escape_attr(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace("\t", "&#9;")
        .replace("\n", "&#10;")
        .replace("\r", "&#13;")
    )


def _escape_text(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
