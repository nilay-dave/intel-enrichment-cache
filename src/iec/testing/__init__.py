"""Test and benchmark helpers that are part of the package.

The virtual clock lives here rather than under tests/ because the benchmark
needs it too, and the first version of the benchmark proved what happens
otherwise: it wrote its own four line clock, the same naive one this package's
own docstring explains is wrong, and reported hedging as having no effect
because concurrent sleeps were being serialised. Shipping the correct one and
importing it in both places is how that stops happening.
"""

from iec.testing.clock import VirtualClock

__all__ = ["VirtualClock"]
