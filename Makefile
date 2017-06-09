init:
    pip install -r requirements.txt

test:
    py.test tests

install: .PHONY

.PHONY: init test