.PHONY: test lint coverage install dev clean

install:
	pip install -e .

dev:
	pip install -e .[all]
	pip install pytest ruff coverage

test:
	pytest tests/ -v --tb=short

lint:
	ruff check sovereign_vault/

coverage:
	pytest --cov=sovereign_vault --cov-report=html --cov-report=term-missing tests/
	echo "Coverage report: htmlcov/index.html"

clean:
	rm -rf build/ dist/ *.egg-info htmlcov/ .coverage .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
