#!/usr/bin/env python
from __future__ import annotations

import argparse
import logging
import sys
from importlib import import_module
from itertools import islice
from pathlib import Path
from textwrap import indent
from urllib.parse import parse_qsl, urlencode, urlparse
from zipimport import zipimporter

import flow.record.adapter
from flow.record import RecordWriter, iter_timestamped_records, record_stream
from flow.record.context import AppContext, get_app_context
from flow.record.selector import make_selector
from flow.record.stream import RecordFieldRewriter
from flow.record.utils import LOGGING_TRACE_LEVEL, catch_sigpipe

try:
    from flow.record.version import version
except ImportError:
    version = "unknown"

try:
    import tqdm

    HAS_TQDM = True

except ImportError:
    HAS_TQDM = False

try:
    import structlog

    HAS_STRUCTLOG = True

except ImportError:
    HAS_STRUCTLOG = False


log = logging.getLogger(__name__)


def list_adapters() -> None:
    failed = []
    loader = flow.record.adapter.__loader__

    # TODO change to loader.get_resource_reader("flow.record.adapter").contents()
    # once zipimport issue is fixed
    if isinstance(loader, zipimporter):
        adapters = [
            Path(path).stem
            for path in loader._files
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
        except ImportError as reason:  # noqa: PERF203
            failed.append((adapter, reason))

    if failed:
        print("unavailable adapters:")
        print("\n".join(indent(f"{adapter}: {reason}", prefix="  ") for adapter, reason in failed))


if HAS_TQDM:
    import threading

    class ProgressMonitor:
        """Periodically update ``progress_bar`` with the record metrics from ``ctx``."""

        def __init__(self, ctx: AppContext, progress_bar: tqdm, update_interval: float = 0.2) -> None:
            self.ctx = ctx
            self.progress_bar = progress_bar
            self.update_interval = update_interval
            self.should_stop = threading.Event()
            self.thread = None

        def start(self) -> None:
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()

        def stop(self) -> None:
            self.update_progress_bar()
            self.progress_bar.set_description_str("Processed")
            self.progress_bar.refresh()
            self.progress_bar.close()

            if self.thread:
                self.should_stop.set()
                self.thread.join(timeout=2.0)

        def _monitor_loop(self) -> None:
            while not self.should_stop.wait(self.update_interval):
                self.update_progress_bar()

        def update_progress_bar(self) -> None:
            source_count = self.ctx.source_count
            source_total = self.ctx.source_total
            read = self.ctx.read
            matched = self.ctx.matched
            unmatched = self.ctx.unmatched
            source = f"{source_count}/{source_total}"

            self.progress_bar.n = read
            postfix = f"{source=!s}, {read=}, {matched=}, {unmatched=}"
            self.progress_bar.set_postfix_str(postfix, refresh=False)
            self.progress_bar.update(0)


@catch_sigpipe
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Record dumper, a tool that can read, write and filter records",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--version", action="version", version=f"flow.record version {version}")
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
        "-n",
        "--no-compile",
        action="store_true",
        help="Don't use a compiled selector (safer, but slower)",
    )
    misc.add_argument("--record-source", default=None, help="Overwrite the record source field")
    misc.add_argument(
        "--record-classification",
        default=None,
        help="Overwrite the record classification field",
    )

    selection = parser.add_argument_group("selection")
    selection.add_argument(
        "-F",
        "--fields",
        metavar="FIELDS",
        help="Fields (comma seperated) to output in dumping",
    )
    selection.add_argument(
        "-X",
        "--exclude",
        metavar="FIELDS",
        help="Fields (comma seperated) to exclude in dumping",
    )
    selection.add_argument(
        "-s",
        "--selector",
        metavar="SELECTOR",
        default=None,
        help="Only output records matching Selector",
    )

    output = parser.add_argument_group("output control")
    output.add_argument("-f", "--format", metavar="FORMAT", help="Format string")
    output.add_argument("-c", "--count", type=int, help="Exit after COUNT records")
    output.add_argument(
        "--skip",
        metavar="COUNT",
        type=int,
        default=0,
        help="Skip the first COUNT records",
    )
    output.add_argument("-w", "--writer", metavar="OUTPUT", default=None, help="Write records to output")
    output.add_argument(
        "-m",
        "--mode",
        default=None,
        choices=("csv", "csv-no-header", "json", "jsonlines", "line", "line-verbose"),
        help="Output mode",
    )
    output.add_argument(
        "--split",
        metavar="COUNT",
        default=None,
        type=int,
        help="Write record files smaller than COUNT records",
    )
    output.add_argument(
        "--suffix-length",
        metavar="LEN",
        default=2,
        type=int,
        help="Generate suffixes of length LEN for splitted output files",
    )
    output.add_argument(
        "--multi-timestamp",
        action="store_true",
        help="Create records for datetime fields",
    )
    output.add_argument(
        "-p",
        "--progress",
        action="store_true",
        help="Show progress bar (requires tqdm)",
    )
    output.add_argument(
        "-t",
        "--total",
        type=int,
        default=None,
        help="The number of expected records, used for progress bar (requires tqdm)",
    )
    output.add_argument(
        "--stats",
        action="store_true",
        help="Show count of processed records",
    )

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
    aliases.add_argument(
        "-Lv",
        "--line-verbose",
        action="store_const",
        const="line-verbose",
        dest="mode",
        default=argparse.SUPPRESS,
        help="Short for --mode=line-verbose",
    )
    aliases.add_argument(
        "-Cn",
        "--csv-no-header",
        action="store_const",
        const="csv-no-header",
        dest="mode",
        default=argparse.SUPPRESS,
        help="Short for --mode=csv-no-header",
    )

    args = parser.parse_args(argv)

    levels = [logging.WARNING, logging.INFO, logging.DEBUG, LOGGING_TRACE_LEVEL]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")

    if HAS_STRUCTLOG:
        # We have structlog, configure Python logging to use it for rendering
        console_renderer = structlog.dev.ConsoleRenderer()
        handler = logging.StreamHandler()
        handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processor=console_renderer,
                foreign_pre_chain=[
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    structlog.processors.TimeStamper(fmt="iso"),
                ],
            )
        )

        # Clear existing handlers and add our structlog handler
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.addHandler(handler)

    fields_to_exclude = args.exclude.split(",") if args.exclude else []
    fields = args.fields.split(",") if args.fields else []

    if args.list_adapters:
        list_adapters()
        return 0

    uri = args.writer or "text://"
    if not args.writer:
        mode_to_uri = {
            "csv": "csvfile://",
            "csv-no-header": "csvfile://?header=false",
            "json": "jsonfile://?indent=2&descriptors=false",
            "jsonlines": "jsonfile://?descriptors=false",
            "line": "line://",
            "line-verbose": "line://?verbose=true",
        }
        uri = mode_to_uri.get(args.mode, uri)
        qparams = {
            "fields": args.fields,
            "exclude": args.exclude,
            "format_spec": args.format,
        }
        query = urlencode({k: v for k, v in qparams.items() if v})
        uri += f"&{query}" if urlparse(uri).query else f"?{query}"

    if args.split:
        if not args.writer:
            parser.error("--split only makes sense in combination with -w/--writer")

        uri = f"split://{uri}" if "://" not in uri else f"split+{uri}"
        parsed = urlparse(uri)
        query_dict = dict(parse_qsl(parsed.query))
        query_dict.update({"count": args.split, "suffix-length": args.suffix_length})
        query = urlencode(query_dict)
        uri = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

    record_field_rewriter = None
    if fields or fields_to_exclude or args.exec_expression:
        record_field_rewriter = RecordFieldRewriter(fields, fields_to_exclude, args.exec_expression)

    selector = make_selector(args.selector, not args.no_compile)
    seen_desc = set()
    islice_stop = (args.count + args.skip) if args.count else None
    record_iterator = islice(record_stream(args.src, selector), args.skip, islice_stop)

    ctx = get_app_context()
    ctx.source_total = len(args.src)
    progress_monitor = None
    progress_bar = None

    if args.total and not HAS_TQDM:
        parser.error("tqdm is required for -t/--total option")

    if args.progress:
        if not HAS_TQDM:
            parser.error("tqdm is required for -p/--progress option")

        progress_bar = tqdm.tqdm(
            total=args.total,
            unit=" records",
            delay=sys.float_info.min,
            desc="Processing",
        )
        progress_monitor = ProgressMonitor(ctx, progress_bar, update_interval=0.2)
        progress_monitor.start()

    count = 0
    record_writer = None
    ret = 0

    try:
        record_writer = RecordWriter(uri)
        for count, rec in enumerate(record_iterator, start=1):  # noqa: B007
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

    except Exception as e:
        print_error(e)

        # Prevent throwing an exception twice when deconstructing the record writer.
        if hasattr(record_writer, "exception") and record_writer.exception is e:
            record_writer.exception = None

        ret = 1

    finally:
        if progress_monitor:
            progress_monitor.stop()
        if record_writer:
            # Exceptions raised in threads can be thrown when deconstructing the writer.
            try:
                record_writer.__exit__()
            except Exception as e:
                print_error(e)
                ret = 1

    if (args.list or args.stats) and not args.progress:
        stats = f"Processed {ctx.read} records (matched={ctx.matched}, unmatched={ctx.unmatched})"
        print(stats, file=sys.stdout if args.list else sys.stderr)

    return ret


def print_error(e: Exception) -> None:
    log.error("rdump encountered a fatal error: %s", e)
    if log.isEnabledFor(LOGGING_TRACE_LEVEL):
        log.exception("Full traceback")


if __name__ == "__main__":
    sys.exit(main())
