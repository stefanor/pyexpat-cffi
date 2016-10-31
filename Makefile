pyexpat/_expat.so: pyexpat/expat_build.py
	python $^

.PHONY: test
test: pyexpat/__init__.py pyexpat/_expat.so
	python test/test_pyexpat.py
	PYTHONPATH=. python test/test_pyexpat.py
