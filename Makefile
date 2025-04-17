# Détection de Python
PYTHON = python

# Variables d'environnement
VENV = .venv
VENV_BIN = $(VENV)/bin
ifeq ($(OS),Windows_NT)
    VENV_BIN = $(VENV)/Scripts
    PYTHON_VENV = $(VENV_BIN)/python.exe
    RM = rd /s /q
else
    PYTHON_VENV = $(VENV_BIN)/python
    RM = rm -rf
endif

.PHONY: install test lint format check clean

# Cible par défaut
all: venv install lint format

# Créer l'environnement virtuel
venv:
	@echo "Création de l'environnement virtuel avec $(PYTHON)..."
	$(PYTHON) -m venv $(VENV)
	@echo "Environnement virtuel créé dans le dossier $(VENV)"
	@echo "Pour l'activer manuellement:"
ifeq ($(OS),Windows_NT)
	@echo "  $(VENV_BIN)/activate.bat"
else
	@echo "  source $(VENV_BIN)/activate"
endif

# Installation des dépendances dans l'environnement virtuel
install: venv
	@echo "Installation des dépendances..."
	$(PYTHON_VENV) -m pip install --upgrade pip
	$(PYTHON_VENV) -m pip install -r requirements-dev.txt
	$(PYTHON_VENV) -m pip install flake8 pylint black pytest pytest-cov

# Supprimer l'environnement virtuel
clean-venv:
	$(RM) $(VENV)

run:
	python src/app.py

test:
	pytest tests/ -v

# Set up tests certs (Download google.com and store its cert chain)
setup:
ifeq ($(OS),Windows_NT)
	@echo "Setting up test certificates for Windows..."
	if not exist tests\certs mkdir tests\certs
	powershell -Command "echo '' | openssl s_client -connect google.com:443 -servername google.com -showcerts | Out-File -FilePath tests\certs\google_certs.txt -Encoding ASCII"
	powershell -Command "$$lines = Get-Content tests\certs\google_certs.txt; $$certs = @(); $$inside = $$false; $$current = @(); foreach ($$line in $$lines) { if ($$line -match '-----BEGIN CERTIFICATE-----') { $$inside = $$true; $$current = @(); }; if ($$inside) { $$current += $$line }; if ($$line -match '-----END CERTIFICATE-----') { $$inside = $$false; $$certs += ,(@($$current) -join \"`n\") } }; $$i = 1; foreach ($$cert in $$certs) { $$cert | Out-File -FilePath (\"tests\\certs\\google_cert_$$i.pem\") -Encoding ASCII; $$i++ }"
	move tests\certs\google_cert_1.pem tests\certs\google_cert_chain.pem
	move tests\certs\google_cert_2.pem tests\certs\google_cert_root.pem
	del tests\certs\google_certs.txt

	powershell -Command "echo '' | openssl s_client -connect facebook.com:443 -servername facebook.com -showcerts | Out-File -FilePath tests\certs\facebook_certs.txt -Encoding ASCII"
	powershell -Command "$$lines = Get-Content tests\certs\facebook_certs.txt; $$certs = @(); $$inside = $$false; $$current = @(); foreach ($$line in $$lines) { if ($$line -match '-----BEGIN CERTIFICATE-----') { $$inside = $$true; $$current = @(); }; if ($$inside) { $$current += $$line }; if ($$line -match '-----END CERTIFICATE-----') { $$inside = $$false; $$certs += ,(@($$current) -join \"`n\") } }; $$i = 1; foreach ($$cert in $$certs) { $$cert | Out-File -FilePath (\"tests\\certs\\facebook_cert_$$i.pem\") -Encoding ASCII; $$i++ }"
	move tests\certs\facebook_cert_1.pem tests\certs\facebook_cert_chain_rsa.pem
	move tests\certs\facebook_cert_2.pem tests\certs\facebook_cert_root_rsa.pem
	del tests\certs\facebook_certs.txt
else
	@echo "Setting up test certificates for Unix/Linux..."
	mkdir -p tests/certs
	openssl s_client -connect google.com:443 -servername google.com -showcerts < /dev/null 2>/dev/null \
	| awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/{print}' \
	| awk 'BEGIN{c=0} /-----END CERTIFICATE-----/ {c++} {print > "tests/certs/google_cert_" c ".pem"}'
	mv tests/certs/google_cert_1.pem tests/certs/google_cert_chain.pem
	mv tests/certs/google_cert_2.pem tests/certs/google_cert_root.pem
endif

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-e2e:
	pytest tests/e2e/ -v

coverage:
	pytest --cov=./ --cov-report=term-missing

coverage-html:
	pytest --cov=./ --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

coverage-xml:
	pytest --cov=./ --cov-report=xml
	@echo "Coverage report generated in coverage.xml"

lint:
	flake8 app models services tests
	pylint app/**/*.py models/**/*.py services/**/*.py tests/**/*.py

format:
	black .

check:
	python scripts/lint.py

clean:
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -r {} +
	find . -type d -name "*.egg" -exec rm -r {} +
	find . -type d -name ".pytest_cache" -exec rm -r {} +
	find . -type d -name ".mypy_cache" -exec rm -r {} +
	find . -type d -name "htmlcov" -exec rm -r {} +
	rm -rf tests/__pycache__*.pyc
