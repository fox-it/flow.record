from __future__ import print_function


def main(glob):
    for var, val in sorted(glob.items()):
        if not var.startswith("test_"):
            continue

        print("{:40s}".format(var), end="")
        try:
            val()
            print("PASSED")
        except Exception:  # noqa: B902
            print("FAILED")
            import traceback

            traceback.print_exc()
