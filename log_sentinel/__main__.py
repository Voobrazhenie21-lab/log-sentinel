"""Allow execution via `python -m log_sentinel`."""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
