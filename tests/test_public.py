import base64
import copy

from samlwrap.verify import (
    _sign_assertion,
    assertion_batch,
    check_reference_target,
    check_reference_unique,
    find_signatures,
    parse_document,
    verify_signature,
)

KEY = b"public-test-signing-key"

DESTINATION = "https://sp.example/saml"


def _signature_block(reference_uri):
    return (
        "<Signature>"
        "<SignedInfo>"
        '<CanonicalizationMethod Algorithm="exact"/>'
        '<SignatureMethod Algorithm="hmac-sha256"/>'
        f'<Reference URI="{reference_uri}">'
        '<DigestMethod Algorithm="sha256"/>'
        "<DigestValue/>"
        "</Reference>"
        "</SignedInfo>"
        "<SignatureValue/>"
        "</Signature>"
    )


def _assertion_block(
    assertion_id,
    *,
    audience=DESTINATION,
    name="alice@example.com",
    role="analyst",
    include_signature=True,
    reference_uri=None,
):
    signature = ""
    if include_signature:
        signature = _signature_block(reference_uri or "#" + assertion_id)
    return (
        f'<Assertion ID="{assertion_id}">'
        "<Issuer>https://idp.example</Issuer>"
        f"<Subject><NameID>{name}</NameID></Subject>"
        "<Conditions>"
        "<AudienceRestriction>"
        f"<Audience>{audience}</Audience>"
        "</AudienceRestriction>"
        "</Conditions>"
        "<AttributeStatement>"
        '<Attribute Name="role">'
        f"<AttributeValue>{role}</AttributeValue>"
        "</Attribute>"
        "</AttributeStatement>"
        f"{signature}"
        "</Assertion>"
    )


def _response(*assertions, destination=DESTINATION):
    return (
        f'<Response Destination="{destination}">'
        + "".join(assertions)
        + "</Response>"
    )


def _by_id(doc, assertion_id):
    return next(node for node in doc.iter() if node.get("ID") == assertion_id)


def _signature_value(doc):
    signature = find_signatures(doc)[0]
    return next(node for node in signature if node.tag == "SignatureValue")


def test_parse_document_keeps_signature_attached_to_assertion():
    doc = parse_document(
        _response(
            _assertion_block("public-parse-a"),
            _assertion_block(
                "public-parse-b",
                name="mallory@example.com",
                include_signature=False,
            ),
        )
    )
    _sign_assertion(doc, KEY)
    original = _by_id(doc, "public-parse-a")
    forged = _by_id(doc, "public-parse-b")
    signature = find_signatures(doc)[0]
    original.remove(signature)
    forged.append(signature)

    assert doc.tag == "Response"
    assert sum(node.tag == "Assertion" for node in doc.iter()) == 2
    assert len(find_signatures(doc)) == 1
    assert verify_signature(doc, KEY) is False


def test_reference_identifiers_must_be_unique():
    doc = parse_document(_response(_assertion_block("public-ref-unique")))
    _sign_assertion(doc, KEY)
    signature = find_signatures(doc)[0]
    signed_info = signature[0]
    reference = next(
        node for node in signed_info if node.tag == "Reference"
    )
    signed_info.append(copy.deepcopy(reference))

    assert check_reference_unique(doc) is False


def test_reference_target_must_match_signed_digest():
    doc = parse_document(_response(_assertion_block("public-ref-target")))
    _sign_assertion(doc, KEY)
    reference = next(
        node
        for node in find_signatures(doc)[0].iter()
        if node.tag == "Reference"
    )
    digest = next(
        node for node in reference if node.tag == "DigestValue"
    )
    digest.text = base64.b64encode(b"forged payload").decode("ascii")

    assert check_reference_target(doc, "#public-ref-target") is False


def test_signature_verification_covers_all_assertion_fields():
    doc = parse_document(_response(_assertion_block("public-coverage")))
    _sign_assertion(doc, KEY)
    value = next(
        node
        for node in doc.iter()
        if node.tag == "AttributeValue"
    )
    value.text = "admin"

    assert verify_signature(doc, KEY) is False


def test_batch_verification_keeps_documents_independent():
    first = parse_document(_response(_assertion_block("public-batch-a")))
    second = parse_document(_response(_assertion_block("public-batch-b")))
    _sign_assertion(first, KEY)
    _sign_assertion(second, KEY)
    _signature_value(second).text = base64.b64encode(b"\x00" * 32).decode(
        "ascii"
    )

    report = assertion_batch([first, second], KEY)

    assert report["results"][0]["ok"] is True
    assert report["results"][1]["ok"] is False