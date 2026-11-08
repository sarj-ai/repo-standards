import hashlib
import json

from repo_standards.core.activation_receipt import (
    ActivationBinding,
    ActivationChange,
    exact_registered_activation,
    exact_registered_append,
    matches_activation_payload,
)


def test_payload_binds_every_identity_and_rejects_extra_or_duplicate_fields():
    binding = ActivationBinding(
        "sarj-ai/platform",
        123,
        "dev",
        "a" * 40,
        "automation/flags/dev/example",
        "b" * 40,
        "dev",
        "c" * 40,
        "e" * 40,
        "example",
        (ActivationChange("flags/dev.json", "f" * 64, "d" * 64),),
    )
    payload = binding.payload()
    assert matches_activation_payload(json.dumps(payload).encode(), binding)
    for key in payload:
        changed = payload | {key: "spoofed"}
        assert not matches_activation_payload(json.dumps(changed).encode(), binding)
    assert not matches_activation_payload(json.dumps(payload | {"extra": True}).encode(), binding)
    raw = json.dumps(payload).encode()
    assert not matches_activation_payload(raw[:-1] + b',"schema_version":1}', binding)
    assert not matches_activation_payload(b'{"schema_version":true}', binding)
    assert not matches_activation_payload(b"\xff", binding)


def test_registered_edit_preserves_every_other_byte():
    before = b'{"example": false, "operational": false}\n'
    after = b'{"example": true, "operational": false}\n'

    def accepts(candidate: bytes, source: bytes = before) -> bool:
        return exact_registered_activation(
            base_content=source,
            head_content=candidate,
            registered_false=b'"example": false',
            registered_true=b'"example": true',
            expected_content_sha256=hashlib.sha256(after).hexdigest(),
        )

    assert accepts(after)
    assert not accepts(after + b" ")
    assert not accepts(after.replace(b'"operational": false', b'"operational": true'))
    assert not accepts(after, before + before)
    assert not accepts(before)


def test_registered_append_preserves_exact_generator_bytes():
    before = b"operational = false\n\n"
    literal = b"model_catalog_enabled = true"
    after = before.rstrip() + b"\n" + literal + b"\n"

    def accepts(candidate: bytes, source: bytes = before) -> bool:
        return exact_registered_append(
            base_content=source,
            head_content=candidate,
            registered_true=literal,
            expected_content_sha256=hashlib.sha256(candidate).hexdigest(),
        )

    assert accepts(after)
    assert not accepts(after + literal + b"\n")
    assert not accepts(after.replace(b"operational = false", b"operational = true"))
    assert not accepts(after + b"unexpected = true\n")
    assert not accepts(after, after)
