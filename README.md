# flow.record

A library for defining and creating structured data (called records) that can be streamed to disk or piped to other
tools that use `flow.record`.

Records can be read and transformed to other formats by using output adapters, such as CSV and JSON.

For more information on how Dissect uses this library, please see [the
documentation](https://docs.dissect.tools/en/latest/tools/rdump.html#what-is-a-record).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`flow.record` is available on [PyPI](https://pypi.org/project/flow.record/).

```bash
pip install flow.record
```

## Usage

This library contains the tool `rdump`. With `rdump` you can read, write, interact, and manipulate records from `stdin`
or from record files saved on disk. Please refer to `rdump -h` or to the [`rdump`
documentation](https://docs.dissect.tools/en/latest/tools/rdump.html) for all parameters.

Records are the primary output type when using the various functions of `target-query`. The following command shows how
to pipe record output from `target-query` to `rdump`:

```shell
user@dissect~$ target-query -f runkeys targets/EXAMPLE.vmx | rdump
<windows/registry/run hostname='EXAMPLE' domain='EXAMPLE.local' ts=2022-12-09 12:06:20.037806+00:00 name='OneDriveSetup' path='C:/Windows/SysWOW64/OneDriveSetup.exe /thfirstsetup' key='HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' hive_filepath='C:\\Windows/ServiceProfiles/LocalService/ntuser.dat' username='LocalService' user_sid='S-1-5-19' user_home='%systemroot%\\ServiceProfiles\\LocalService'>
<...>
```

## Programming example

Define a `RecordDescriptor` (schema) and then create a few records and write them to disk

```python
from flow.record import RecordDescriptor, RecordWriter

# define our descriptor
MyRecord = RecordDescriptor("my/record", [
    ("net.ipaddress", "ip"),
    ("string", "description"),
])

# define some records
records = [
    MyRecord("1.1.1.1", "cloudflare dns"),
    MyRecord("8.8.8.8", "google dns"),
]

# write the records to disk
with RecordWriter("output.records.gz") as writer:
    for record in records:
        writer.write(record)
```

The records can then be read from disk using the `rdump` tool or by instantiating a `RecordReader` when using the
library.

```shell
$ rdump output.records.gz
<my/record ip=net.ipaddress('1.1.1.1') description='cloudflare dns'>
<my/record ip=net.ipaddress('8.8.8.8') description='google dns'>
```

### Declarative record definitions

Instead of with a `RecordDescriptor`, records can also be defined by subclassing `RecordBase` and annotating the
fields, like a `dataclass`:

```python
from datetime import datetime
from typing import Annotated

from flow.record.declarative import RecordBase, field


class HttpRequestRecord(RecordBase, name="http/request"):
    ts: datetime
    url: str  # Python types map to a field type, e.g. str to string
    status: Annotated[int, "uint32"]  # or field(typename="uint32")
    remote: str


record = HttpRequestRecord(ts=datetime.now(), url="http://flow.record", status=200, remote="127.0.0.1")
```

Every field can be `None`, so `X | None` is technically the more correct type hint.
A field annotated with `X | None` has the same field type as `X`.

A subclass starts with the fields of its parent:

```python
class HttpResponseRecord(HttpRequestRecord, name="http/response"):
    body: bytes
```

A field can have a default (`status: int = 200`), or be set in a `__post_init__` method with `field(init=False)`.
The `__post_init__` method receives the `InitVar` arguments of the constructor:

```python
from dataclasses import InitVar


class HostRecord(RecordBase, name="example/host"):
    hostname: str = field(init=False)
    target: InitVar[object]

    def __post_init__(self, target: object) -> None:
        self.hostname = target.hostname
```

The declarative class is currently mostly a nicety for type checking. Internally, it defines a regular
`RecordDescriptor`, and packing a record only stores that descriptor and the field values. So
declarative records don't round-trip: unpacking one returns a record of the record class of the descriptor,
not an instance of the declarative class.

> [!NOTE]
> Field annotations are evaluated when the class is created. If your project uses Ruff's `flake8-type-checking` (`TC`)
> rules, add `RecordBase` to the runtime-evaluated base classes, so that imports only used in field annotations are not
> moved into a `TYPE_CHECKING` block:
>
> ```toml
> [tool.ruff.lint.flake8-type-checking]
> runtime-evaluated-base-classes = ["flow.record.declarative.RecordBase"]
> ```

### Selectors

We can also use `selectors` for filtering and selecting records using a query (Python like syntax), e.g.:

```shell
$ rdump output.records.gz -s '"google" in r.description'
<my/record ip=net.ipaddress('8.8.8.8') description='google dns'>

$ rdump output.records.gz -s 'r.ip in net.ipnetwork("1.1.0.0/16")'
<my/record ip=net.ipaddress('1.1.1.1') description='cloudflare dns'>
```

## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.
