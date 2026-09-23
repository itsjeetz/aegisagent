.PHONY: setup test serve eval fixtures redteam claims clean

PYTHON ?= python

setup:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m pytest tests/ -v

serve:
	$(PYTHON) -m uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload

eval:
	$(PYTHON) -m eval.run_eval --split dev --out reports/

fixtures:
	$(PYTHON) -m eval.fixture_factory

redteam:
	$(PYTHON) -m eval.redteam

claims:
	$(PYTHON) -m eval.claims

clean:
	rm -rf __pycache__ .pytest_cache .coverage reports/
