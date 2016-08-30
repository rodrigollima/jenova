# Tests
This is simple guide how to run tests and create new ones.

## Running
Because our tests has dependencies you must set your PYTHONPATH environment variable:
```sh
cd jenova/src
export PYTHONPATH="${PWD}"
```

For a single test run:
```sh
cd test/
python tests/your_tests.py
```

Running all tests:
```sh
cd test/
python run_tests.py
```

## Creating new tests
There is a test template that you can use as base to begin your tests:
```
jenova/src/test/template_tests.py
```