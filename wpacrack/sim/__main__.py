"""Generate the checked-in fixture set: python -m wpacrack.sim [out_dir]"""

import os
import sys

from . import write_default_fixtures

if __name__ == "__main__":
    if len(sys.argv) > 1:
        out_dir = os.path.abspath(sys.argv[1])
    else:
        out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "fixtures"))
    path = write_default_fixtures(out_dir)
    print("fixtures written to", path)
