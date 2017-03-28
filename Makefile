.PHONY: clean

init:
	pip3 install -r requirements.txt

test: clean
	nosetests -vv tests

clean:
	@find . -name *.pyc -delete; rm .coverage 2> /dev/null || true
