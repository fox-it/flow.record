from __future__ import annotations

import sys
from io import BytesIO
from typing import Any, Generator, Iterator
from unittest.mock import MagicMock, patch

import pytest

from flow.record import Record, RecordAdapter, RecordDescriptor, RecordStreamWriter
from flow.record.base import GZIP_MAGIC


def generate_records(amount) -> Generator[Record, Any, None]:
    TestRecordWithFooBar = RecordDescriptor(
        "test/record",
        [
            ("string", "name"),
            ("string", "foo"),
            ("varint", "idx"),
        ],
    )
    for i in range(amount):
        yield TestRecordWithFooBar(name=f"record{i}", foo="bar", idx=i)


def clean_up_adapter_import(test_function):
    def wrapper(mock_google_sdk):
        try:
            result = test_function(mock_google_sdk)
        finally:
            if "flow.record.adapter.gcs" in sys.modules:
                del sys.modules["flow.record.adapter.gcs"]
        return result

    return wrapper


@pytest.fixture
def mock_google_sdk(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    with monkeypatch.context() as m:
        mock_google_sdk = MagicMock()
        m.setitem(sys.modules, "google", mock_google_sdk)
        m.setitem(sys.modules, "google.cloud", mock_google_sdk.cloud)
        m.setitem(sys.modules, "google.cloud.storage", mock_google_sdk.cloud.storage)
        m.setitem(sys.modules, "google.cloud.storage.client", mock_google_sdk.cloud.storage.client)
        m.setitem(sys.modules, "google.cloud.storage.fileio", mock_google_sdk.cloud.storage.fileio)

        yield mock_google_sdk


@clean_up_adapter_import
def test_gcs_uri_and_path(mock_google_sdk: MagicMock) -> None:
    from flow.record.adapter.gcs import GcsReader

    mock_client = MagicMock()
    mock_google_sdk.cloud.storage.client.Client.return_value = mock_client
    adapter_with_glob = RecordAdapter("gcs://test-bucket/path/to/records/*/*.avro", project="test-project")

    assert isinstance(adapter_with_glob, GcsReader)

    mock_google_sdk.cloud.storage.client.Client.assert_called_with(project="test-project")
    mock_client.bucket.assert_called_with("test-bucket")

    assert adapter_with_glob.prefix == "path/to/records/"
    assert adapter_with_glob.pattern == "path/to/records/*/*.avro"

    adapter_without_glob = RecordAdapter("gcs://test-bucket/path/to/records/test-records.rec", project="test-project")
    assert isinstance(adapter_without_glob, GcsReader)

    assert adapter_without_glob.prefix == "path/to/records/test-records.rec"
    assert adapter_without_glob.pattern is None


@clean_up_adapter_import
def test_gcs_reader_glob(mock_google_sdk) -> None:
    # Create a mocked record stream
    test_records = list(generate_records(10))
    mock_blob = BytesIO()
    writer = RecordStreamWriter(fp=mock_blob)
    for record in test_records:
        writer.write(record)
    writer.flush()
    mock_recordstream = mock_blob.getvalue()
    writer.close()

    # Create a mocked client that will return the test-bucket
    mock_client = MagicMock()
    mock_client.bucket.return_value = "test-bucket-returned-from-client"
    mock_google_sdk.cloud.storage.client.Client.return_value = mock_client

    # Create a mocked instance of the 'Blob' class of google.cloud.storage.fileio
    recordsfile_blob_mock = MagicMock()
    recordsfile_blob_mock.name = "path/to/records/subfolder/results/tests.records"
    recordsfile_blob_mock.data = mock_recordstream
    recordsfile_blob_mock.size = len(mock_recordstream)

    # As this blob is located in the '🍩 select' folder, it should not match with the glob that will be used later
    # (which requires /results/ to be present in the path string)
    wrong_location_blob = MagicMock()
    wrong_location_blob.name = "path/to/records/subfolder/donutselect/tests.records"
    wrong_location_blob.size = 0x69
    wrong_location_blob.data = b""

    # Return one empty file, one file that should match the glob, and one file that shouldn't match the glob
    mock_client.list_blobs.return_value = [MagicMock(size=0), recordsfile_blob_mock, wrong_location_blob]

    test_read_buf = BytesIO(mock_recordstream)
    mock_reader = MagicMock(wraps=test_read_buf, spec=BytesIO)
    mock_reader.closed = False
    mock_google_sdk.cloud.storage.fileio.BlobReader.return_value = mock_reader
    with patch("io.open", MagicMock(return_value=mock_reader)):
        adapter = RecordAdapter(
            url="gcs://test-bucket/path/to/records/*/results/*.records",
            project="test-project",
            selector="r.idx >= 5",
        )

        found_records = list(adapter)
        mock_client.bucket.assert_called_with("test-bucket")
        mock_client.list_blobs.assert_called_with(
            bucket_or_name="test-bucket-returned-from-client",
            prefix="path/to/records/",
        )

    # We expect the GCS Reader to skip over blobs of size 0, as those will inherently not contain records.
    # Thus, a BlobReader should only have been initialized once, for the mocked records blob.
    mock_google_sdk.cloud.storage.fileio.BlobReader.assert_called_once()

    # We expect 5 records rather than 10 because of the selector that we used
    assert len(found_records) == 5
    for record in found_records:
        assert record.foo == "bar"
        assert record == test_records[record.idx]

    adapter.close()
    mock_client.close.assert_called()


@clean_up_adapter_import
def test_gcs_writer(mock_google_sdk) -> None:
    from flow.record.adapter.gcs import GcsWriter

    test_buf = BytesIO()
    mock_writer = MagicMock(wraps=test_buf, spec=BytesIO)
    mock_google_sdk.cloud.storage.fileio.BlobWriter.return_value = mock_writer

    adapter = RecordAdapter("gcs://test-bucket/test/test.records.gz", project="test-project", out=True)

    assert isinstance(adapter, GcsWriter)

    # Add mock records
    test_records = list(generate_records(10))
    for record in test_records:
        adapter.write(record)

    adapter.flush()
    mock_writer.flush.assert_called()

    # Grab the bytes before it's too late
    written_bytes = test_buf.getvalue()
    assert written_bytes.startswith(GZIP_MAGIC)

    read_buf = BytesIO(test_buf.getvalue())

    # Close the writer and assure the object has been closed
    adapter.close()
    mock_writer.close.assert_called()
    assert test_buf.closed

    # Verify if the written record stream is something we can read
    reader = RecordAdapter(fileobj=read_buf)
    read_records = list(reader)
    assert len(read_records) == 10
    for idx, record in enumerate(read_records):
        assert record == test_records[idx]
