.PHONY: unit smoke e2e test clean compile

unit:
	pytest tests/unit

smoke:
	pytest tests/smoke

e2e:
	pytest tests/e2e

test: unit smoke e2e

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

compile:
	python3 -m compileall src
