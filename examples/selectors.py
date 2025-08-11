from __future__ import annotations

from flow.record import RecordDescriptor
from flow.record.selector import Selector

desc = RecordDescriptor(
    "test/samplerecord",
    [
        ("uint16", "value"),
        ("string", "x"),
    ],
)


def main() -> None:
    s_str = "r.x == u'\\u2018Test\\u2019' or r.value == 17 or (r.value == 1337 and r.x == 'YOLO')"
    print(f"Evaluating selector.... \n{s_str}")
    print("\n")
    s = Selector(s_str)
    obj = desc(0, "Test")
    obj.x = "\u2018Test\u2019"
    obj.value = 16
    val = s.explain_selector(obj)
    print(val.backtrace())


if __name__ == "__main__":
    main()


"""
r.x == 'Test' or r.value == 17      -> True
    r.x == 'Test'                   -> True
        or
    r.value == 17                   -> False

"""
