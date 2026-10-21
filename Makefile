# PYTHON is the interpreter everything runs through. The console scripts pip
# installs bind to whichever interpreter installed them, which on a machine with
# several Pythons is not necessarily the one on PATH. Running modules through an
# explicit interpreter removes that class of "works for me" report.
# Override with: make verify PYTHON=python3.12
PYTHON ?= python3

.PHONY: install verify test lint bench stream docs clean

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check src tests tools benchmark scripts

test:
	$(PYTHON) -m pytest --cov=iec --cov-report=term-missing --cov-report=xml

# Runs every check CI runs, in the same order, so a green local verify means a
# green build. A verify that is a subset of CI is a verify that lies.
verify: lint test
	$(PYTHON) tools/check_dashes.py
	$(PYTHON) tools/check_tables.py
	$(PYTHON) tools/check_dependencies.py
	$(PYTHON) tools/check_numbers.py
	$(PYTHON) scripts/provenance_check.py

# Regenerates docs/metrics.json. Experiments A and B are deterministic;
# experiment C sleeps the simulated delays for real, so this takes minutes.
bench:
	$(PYTHON) benchmark/run_benchmark.py

# The properties of a generated stream on its own, for arguing with the model
# without running the whole benchmark.
stream:
	$(PYTHON) benchmark/stream.py --length 10000 --universe 2000

docs:
	$(PYTHON) -m mkdocs build --strict --site-dir public

clean:
	rm -rf .pytest_cache .ruff_cache htmlcov coverage.xml .coverage build dist public
	rm -f *.sqlite *.sqlite-wal *.sqlite-shm
