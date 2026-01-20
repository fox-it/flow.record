import pytest

from flow.record import RecordDescriptor

# Valid digest values for testing
MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

MD5_BYTES = bytes.fromhex(MD5)
SHA1_BYTES = bytes.fromhex(SHA1)
SHA256_BYTES = bytes.fromhex(SHA256)


def test_digest_invalid_value() -> None:
    """Test that setting an invalid digest value raises TypeError and does not modify the original value."""

    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("digest", "digest"),
        ],
    )

    record = TestRecord((MD5, SHA1, SHA256))
    assert record.digest.md5 == MD5
    assert record.digest.sha1 == SHA1
    assert record.digest.sha256 == SHA256

    with pytest.raises(TypeError, match=r"Invalid MD5 value 'aa', Incorrect hash length"):
        record.digest.md5 = "aa"

    with pytest.raises(TypeError, match=r"Invalid SHA-1 value 'aa', Incorrect hash length"):
        record.digest.sha1 = "aa"

    with pytest.raises(TypeError, match=r"Invalid SHA-256 value 'aa', Incorrect hash length"):
        record.digest.sha256 = "aa"

    with pytest.raises(TypeError, match=r"Incorrect binary MD5 hash length: 2, expected 16"):
        record.digest.md5 = b"aa"

    with pytest.raises(TypeError, match=r"Incorrect binary SHA-1 hash length: 2, expected 20"):
        record.digest.sha1 = b"aa"

    with pytest.raises(TypeError, match=r"Incorrect binary SHA-256 hash length: 2, expected 32"):
        record.digest.sha256 = b"aa"

    with pytest.raises(TypeError, match=r"Invalid MD5 value '.*', Non-hexadecimal digit found"):
        record.digest.md5 = "z" * 32

    with pytest.raises(TypeError, match=r"Invalid SHA-1 value '.*', Non-hexadecimal digit found"):
        record.digest.sha1 = "z" * 40

    with pytest.raises(TypeError, match=r"Invalid SHA-256 value '.*', Non-hexadecimal digit found"):
        record.digest.sha256 = "z" * 64

    assert record.digest.md5 == MD5
    assert record.digest.sha1 == SHA1
    assert record.digest.sha256 == SHA256


@pytest.mark.parametrize(
    "digest_value",
    [
        (MD5, SHA1, SHA256),
        {"md5": MD5, "sha1": SHA1, "sha256": SHA256},
        (MD5_BYTES, SHA1_BYTES, SHA256_BYTES),
        {"md5": MD5_BYTES, "sha1": SHA1_BYTES, "sha256": SHA256_BYTES},
    ],
)
def test_digest_initializers(digest_value: tuple | dict) -> None:
    """Test that digest field can be set and retrieved from tuple, dictionary, and bytes initializers."""
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("digest", "digest"),
        ],
    )

    record = TestRecord(digest=digest_value)
    assert record.digest.md5 == MD5
    assert record.digest.sha1 == SHA1
    assert record.digest.sha256 == SHA256


def test_digest_to_dict() -> None:
    """Test that digest field can be iterated over to retrieve md5, sha1, and sha256 values."""

    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("digest", "digest"),
        ],
    )

    record = TestRecord(digest=(MD5, SHA1, SHA256))
    assert dict(record.digest) == {"md5": MD5, "sha1": SHA1, "sha256": SHA256}
