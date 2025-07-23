.PHONY: help install install-dev test lint format security build clean docker-build docker-run deploy

PYTHON := python3.13
PIP := pip3
PROJECT_NAME := wifite3
VERSION := 3.13.5
IMAGE_NAME := $(PROJECT_NAME):$(VERSION)

help:
	@echo "Wifite3 - Python 3.13.5 Edition - Available commands:"
	@echo "  install        Install the package"
	@echo "  install-dev    Install development dependencies"
	@echo "  test          Run tests with pytest"
	@echo "  lint          Run linting with ruff"
	@echo "  format        Format code with black and ruff"
	@echo "  security      Run security checks with bandit and safety"
	@echo "  build         Build the package"
	@echo "  clean         Clean build artifacts"
	@echo "  docker-build  Build Docker image"
	@echo "  docker-run    Run Docker container"
	@echo "  deploy        Deploy to production"

install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -e .[dev]
	$(PIP) install -r requirements-dev.txt

test:
	$(PYTHON) -m pytest tests/ -v --cov=wifite --cov-report=html --cov-report=term

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy wifite/

format:
	$(PYTHON) -m black .
	$(PYTHON) -m ruff check --fix .

security:
	$(PYTHON) -m bandit -r wifite/
	$(PYTHON) -m safety check

build:
	$(PYTHON) -m build

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .ruff_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

docker-build:
	docker build -f Dockerfile.modern -t $(IMAGE_NAME) .

docker-run:
	docker run --rm -it --privileged --net=host $(IMAGE_NAME)

deploy: clean security lint test build
	@echo "Deploying $(PROJECT_NAME) v$(VERSION)"
	@echo "All checks passed - ready for production deployment"

check-python:
	@$(PYTHON) --version | grep -q "3.13" || (echo "Python 3.13+ required" && exit 1)
	@echo "Python version check passed"

all: check-python install-dev format lint security test build
	@echo "All tasks completed successfully"
