from __future__ import annotations

import argparse
import logging
import random
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import maxminddb

from flow.record import RecordDescriptor, RecordWriter, extend_record, record_stream
from flow.record.utils import catch_sigpipe

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.base import Record

logger = logging.getLogger(__name__)

IPv4Record = RecordDescriptor(
    "geo/ipv4",
    [
        ("net.ipaddress", "ip"),
    ],
)

GeoRecord = RecordDescriptor(
    "maxmind/geo",
    [
        ("string", "country"),
        ("string", "country_code"),
        ("string", "city"),
        ("float", "longitude"),
        ("float", "latitude"),
    ],
)

AsnRecord = RecordDescriptor(
    "maxmind/asn",
    [
        ("string", "asn"),
        ("string", "org"),
    ],
)

DEFAULT_CITY_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
DEFAULT_ASN_DB = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
REGEX_IPV4 = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def georecord_for_ip(city_db: maxminddb.Reader, ip: str) -> Record:
    r = city_db.get(ip) if city_db else None
    if not r:
        return GeoRecord()

    loc_dict = r.get("location", {})
    country_dict = r.get("country", {})
    city_dict = r.get("city", {})

    country = country_dict.get("names", {}).get("en")
    country_code = country_dict.get("iso_code")
    city = city_dict.get("names", {}).get("en")
    lon = loc_dict.get("longitude")
    lat = loc_dict.get("latitude")

    return GeoRecord(
        country=country,
        country_code=country_code,
        city=city,
        longitude=lon,
        latitude=lat,
    )


def asnrecord_for_ip(asn_db: maxminddb.Reader, ip: str) -> Record:
    r = asn_db.get(ip) if asn_db else None
    if not r:
        return AsnRecord()
    asn = r.get("autonomous_system_number", None)
    org = r.get("autonomous_system_organization", None)
    return AsnRecord(asn=asn, org=org)


def ip_records_from_text_files(files: list[str]) -> Iterator[Record]:
    """Yield IPv4Records by extracting IP addresses from `files` using a regex."""
    for fname in files:
        with Path(fname).open() if fname != "-" else sys.stdin as f:
            for line in f:
                for ip in REGEX_IPV4.findall(line):
                    yield IPv4Record(ip)


@catch_sigpipe
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Annotate records with GeoIP and ASN data",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-c", "--city-db", default=DEFAULT_CITY_DB, help="path to GeoIP city database")
    parser.add_argument("-a", "--asn-db", default=DEFAULT_ASN_DB, help="path to GeoIP ASN database")
    parser.add_argument(
        "-i",
        "--ip-field",
        metavar="FIELD",
        default="ip",
        help="the source record field to use for lookups",
    )
    parser.add_argument(
        "-w",
        "--writer",
        metavar="OUTPUT",
        default="-",
        help="write records to output",
    )
    parser.add_argument("input", nargs="*", default=["-"], help="input files")
    parser.add_argument(
        "-t",
        "--text",
        action="store_true",
        help="treats input as text and extract IPv4 Records using regex",
    )

    # Hidden options
    parser.add_argument("-m", "--mode", type=int, default=maxminddb.MODE_AUTO, help=argparse.SUPPRESS)
    parser.add_argument("-g", "--generate", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.generate:
        with RecordWriter() as writer:
            while True:
                record = IPv4Record(random.randint(0, 0xFFFFFFFF))
                writer.write(record)

    if args.mode:
        logger.warning("MODE: %u", args.mode)

    try:
        city_db = maxminddb.open_database(args.city_db, args.mode)
    except FileNotFoundError:
        logger.warning(
            "[*] Disabled Geo record annotation. (database not found: %r)",
            args.city_db,
        )
        city_db = None

    try:
        asn_db = maxminddb.open_database(args.asn_db, args.mode)
    except FileNotFoundError:
        logger.warning("[*] Disabled ASN record annotation. (database not found: %r)", args.asn_db)
        asn_db = None

    if not any([city_db, asn_db]) and not args.text:
        print(
            "[!] Both City and ASN database not available. Nothing to annotate, exiting..",
            file=sys.stderr,
        )
        return 1

    # Input are text files, extract IPv4Records from text using a regex or record files
    record_iterator = ip_records_from_text_files(args.input) if args.text else record_stream(args.input)

    with RecordWriter(args.writer) as writer:
        for record in record_iterator:
            ip = getattr(record, args.ip_field, None)

            annotated_records = []
            if city_db:
                geo_record = georecord_for_ip(city_db, str(ip)) if ip else GeoRecord()
                annotated_records.append(geo_record)
            if asn_db:
                asn_record = asnrecord_for_ip(asn_db, str(ip)) if ip else AsnRecord()
                annotated_records.append(asn_record)

            record = extend_record(record, annotated_records)
            writer.write(record)

    return 0


if __name__ == "__main__":
    sys.exit(main())
