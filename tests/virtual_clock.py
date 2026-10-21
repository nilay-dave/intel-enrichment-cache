"""Re-export, so existing test imports keep working.

The clock itself moved into the package, because the benchmark needs it too.
"""

from iec.testing.clock import VirtualClock

__all__ = ["VirtualClock"]
