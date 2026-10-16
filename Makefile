PYTHON ?= python3

.PHONY: test validate conformance integration

test:
	$(PYTHON) -m unittest discover -s tests -v

validate:
	$(PYTHON) trustbase.py validate
	$(PYTHON) trustbase.py --root examples validate

conformance:
	$(PYTHON) tests/kata_conformance.py

integration:
	$(PYTHON) tests/live_integration.py
