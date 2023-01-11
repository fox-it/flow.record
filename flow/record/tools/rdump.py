#!/usr/bin/env python
from __future__ import print_function

import logging
import sys
from importlib import import_module
from pathlib import Path
from textwrap import indent
from urllib.parse import urlencode, urlparse
from zipimport import zipimporter

import flow.record.adapter
from flow.record import RecordWriter, iter_timestamped_records, record_stream
from flow.record.selector import make_selector
from flow.record.stream import RecordFieldRewriter
from flow.record.utils import catch_sigpipe

try:
    from flow.record.version import version
except ImportError:
    version = "unknown"

log = logging.getLogger(__name__)


def list_adapters():
    failed = []
    loader = flow.record.adapter.__loader__

    # TODO change to loader.get_resource_reader("flow.record.adapter").contents()
    # once zipimport issue is fixed
    if isinstance(loader, zipimporter):
        adapters = [
            Path(path).stem
            for path in loader._files.keys()
            if path.endswith((".py", ".pyc"))
            and not Path(path).name.startswith("__")
            and "flow/record/adapter" in str(Path(path).parent)
        ]
    else:
        adapters = [
            Path(name).stem
            for name in loader.get_resource_reader("flow.record.adapter").contents()
            if name.endswith(("py", "pyc")) and not name.startswith("__")
        ]

    print("available adapters:")
    for adapter in adapters:
        try:
            mod = import_module(f"flow.record.adapter.{adapter}")
            usage = indent(mod.__usage__.strip(), prefix="    ")
            print(f"  {adapter}:\n{usage}\n")
        except ImportError as reason:
            failed.append((adapter, reason))

    if failed:
        print("unavailable adapters:")
        print("\n".join(indent(f"{adapter}: {reason}", prefix="  ") for adapter, reason in failed))


@catch_sigpipe
def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        description="Record dumper, a tool that can read, write and filter records",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--version", action="version", version="flow.record version {}".format(version))
    parser.add_argument("src", metavar="SOURCE", nargs="*", default=["-"], help="Record source")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")

    misc = parser.add_argument_group("miscellaneous")
    misc.add_argument(
        "-a",
        "--list-adapters",
        action="store_true",
        help="List (un)available adapters that can be used for reading or writing",
    )
    misc.add_argument("-l", "--list", action="store_true", help="List unique Record Descriptors")
    misc.add_argument(
        "-n", "--no-compile", action="store_true", help="Don't use a compiled selector (safer, but slower)"
    )
    misc.add_argument("--record-source", default=None, help="Overwrite the record source field")
    misc.add_argument("--record-classification", default=None, help="Overwrite the record classification field")

    selection = parser.add_argument_group("selection")
    selection.add_argument("-F", "--fields", metavar="FIELDS", help="Fields (comma seperated) to output in dumping")
    selection.add_argument("-X", "--exclude", metavar="FIELDS", help="Fields (comma seperated) to exclude in dumping")
    selection.add_argument(
        "-s", "--selector", metavar="SELECTOR", default=None, help="Only output records matching Selector"
    )

    output = parser.add_argument_group("output control")
    output.add_argument("-f", "--format", metavar="FORMAT", help="Format string")
    output.add_argument("-c", "--count", type=int, help="Exit after COUNT records")
    output.add_argument("-w", "--writer", metavar="OUTPUT", default=None, help="Write records to output")
    output.add_argument("-m", "--mode", default=None, choices=("csv", "json", "jsonlines", "line"), help="Output mode")
    output.add_argument("--multi-timestamp", action="store_true", help="Create records for datetime fields")

    advanced = parser.add_argument_group("advanced")
    advanced.add_argument(
        "-E",
        "--exec-expression",
        help="execute a (Python) expression for each record AFTER selector matching, can be used to assign new fields",
    )

    aliases = parser.add_argument_group("aliases")
    aliases.add_argument(
        "-j",
        "--json",
        action="store_const",
        const="json",
        dest="mode",
        default=argparse.SUPPRESS,
        help="Short for --mode=json",
    )
    aliases.add_argument(
        "-J",
        "--jsonlines",
        action="store_const",
        const="jsonlines",
        dest="mode",
        default=argparse.SUPPRESS,
        help="Short for --mode=jsonlines",
    )
    aliases.add_argument(
        "-C",
        "--csv",
        action="store_const",
        const="csv",
        dest="mode",
        default=argparse.SUPPRESS,
        help="Short for --mode=csv",
    )
    aliases.add_argument(
        "-L",
        "--line",
        action="store_const",
        const="line",
        dest="mode",
        default=argparse.SUPPRESS,
        help="Short for --mode=line",
    )

    args = parser.parse_args(argv)

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")

    fields_to_exclude = args.exclude.split(",") if args.exclude else []
    fields = args.fields.split(",") if args.fields else []

    if args.list_adapters:
        list_adapters()
        return 0

    uri = args.writer or "text://"
    if not args.writer:
        mode_to_uri = {
            "csv": "csvfile://",
            "json": "jsonfile://?indent=2&descriptors=false",
            "jsonlines": "jsonfile://?descriptors=false",
            "line": "line://",
        }
        uri = mode_to_uri.get(args.mode, uri)
        qparams = {
            "fields": args.fields,
            "exclude": args.exclude,
            "format_spec": args.format,
        }
        query = urlencode({k: v for k, v in qparams.items() if v})
        uri += "&" if urlparse(uri).query else "?" + query

    record_field_rewriter = None
    if fields or fields_to_exclude or args.exec_expression:
        record_field_rewriter = RecordFieldRewriter(fields, fields_to_exclude, args.exec_expression)

    selector = make_selector(args.selector, not args.no_compile)
    seen_desc = set()
    count = 0
    with RecordWriter(uri) as record_writer:
        for count, rec in enumerate(record_stream(args.src, selector), start=1):
            if args.record_source is not None:
                rec._source = args.record_source
            if args.record_classification is not None:
                rec._classification = args.record_classification
            if record_field_rewriter:
                rec = record_field_rewriter.rewrite(rec)

            if args.list:
                # Dump RecordDescriptors
                desc = rec._desc
                if desc.descriptor_hash not in seen_desc:
                    seen_desc.add(desc.descriptor_hash)
                    print(f"# {desc}")
                    print(desc.definition())
                    print()
            else:
                # Dump Records
                if args.multi_timestamp:
                    for record in iter_timestamped_records(rec):
                        record_writer.write(record)
                else:
                    record_writer.write(rec)

            if args.count and count >= args.count:
                break

    if args.list:
        print("Processed {} records".format(count))


if __name__ == "__main__":
    sys.exit(main())
