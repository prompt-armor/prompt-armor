.PHONY: install test lint format typecheck bench docs clean

install:
	pip install -e ".[dev,mcp]"

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

typecheck:
	mypy src/llm_shield/

bench:
	python tests/benchmark/run_benchmark.py

docs:
	mkdocs serve

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
