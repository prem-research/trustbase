PYTHON ?= python3
PODVM_VERSION ?= 0.3.13
EVALUATOR := tools/kata-policy-eval/target/release/kata-policy-eval

.PHONY: test validate conformance integration evaluator admit

test:
	$(PYTHON) -m unittest discover -s tests -v

validate:
	$(PYTHON) trustbase.py validate
	$(PYTHON) trustbase.py --root examples validate

conformance:
	$(PYTHON) tests/kata_conformance.py

integration:
	$(PYTHON) tests/live_integration.py --podvm-version "$(PODVM_VERSION)"

evaluator:
	cargo build --release --locked --manifest-path tools/kata-policy-eval/Cargo.toml

admit: evaluator
	KATA_POLICY_EVAL=$(EVALUATOR) $(PYTHON) trustbase.py admit --all
	KATA_POLICY_EVAL=$(EVALUATOR) $(PYTHON) trustbase.py --root examples admit --all
