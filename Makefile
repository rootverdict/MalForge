PYTHON ?= python3

.PHONY: install run test lint tree clean

install:
	$(PYTHON) -m pip install -r requirements.txt

run:
	$(PYTHON) main.py --report samples/cuckoo_sample.json

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m compileall .

tree:
	find . -maxdepth 3 | sort

clean:
	find output -type f ! -name '.gitkeep' ! -name '.rule_ids.json' -delete
