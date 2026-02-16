.PHONY: unit smoke e2e

PYTEST ?= python -m pytest

unit:
	$(PYTEST) tests -k "not smoke and not e2e"

smoke:
	$(PYTEST) tests/smoke

e2e:
	$(PYTEST) tests/e2e
