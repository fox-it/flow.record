import random
from datetime import datetime, timezone

from flow import record

UTC_TIMEZONE = timezone.utc

descriptor = """
network/traffic/tcp/connection
    datetime ts;
    net.ipv4.Address src;
    net.tcp.Port srcport;
    net.ipv4.Address dst;
    net.tcp.Port dstport;
"""
conn = record.RecordDescriptor(descriptor)

ip_list = [
    "127.0.0.1",
    "1.2.3.4",
    "212.33.1.45",
    "4.4.4.4",
    "8.8.8.8",
    "212.1.6.1",
]

port_list = [
    22,
    53,
    80,
    443,
    5555,
]

rs = record.RecordWriter()

for _ in range(500):
    r = conn(
        ts=datetime.now(tz=UTC_TIMEZONE),
        src=random.choice(ip_list),
        srcport=random.choice(port_list),
        dst=random.choice(ip_list),
        dstport=random.choice(port_list),
    )

    rs.write(r)
