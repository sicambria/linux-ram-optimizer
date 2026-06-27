# Convenience targets for linux-ram-optimizer. No third-party tools required.
PYTHON ?= python3

.PHONY: help test diagnose free reclaim swap stop install clean check-sensitive

help:
	@echo "Targets:"
	@echo "  make test            Run the unit test suite (no root needed)"
	@echo "  make check-sensitive Scan tracked files for personal/host/secret data"
	@echo "  make diagnose        Run a read-only memory diagnosis"
	@echo "  make free            Show a dry-run cache-reclaim plan (no changes)"
	@echo "  make reclaim         Show a dry-run idle-tmpfs reclaim plan (no changes)"
	@echo "  make swap            Show a dry-run swapfile plan (no changes)"
	@echo "  make stop            Show a dry-run plan to stop non-essential workloads"
	@echo "  make install         Install the ram-optimizer command (runs ./install.sh)"
	@echo "  make clean           Remove caches and build artifacts"

test:
	$(PYTHON) -m unittest discover -s tests -v

# Same scan the pre-push hook runs; safe to run any time.
check-sensitive:
	$(PYTHON) scripts/check_sensitive.py

diagnose:
	$(PYTHON) -m ramopt diagnose

free:
	$(PYTHON) -m ramopt free

reclaim:
	$(PYTHON) -m ramopt reclaim

swap:
	$(PYTHON) -m ramopt swap --size-gb 16

stop:
	$(PYTHON) -m ramopt stop

install:
	./install.sh

clean:
	rm -rf build dist ./*.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
