# Contributing

If you would like to contribute, below you can find some helpful suggestions and instructions.

## Installing from source

To install `suricata-check-design-principles` from source (potentially with local modifications), simply run the following commands:

```bash
git clone https://github.com/Koen1999/suricata-check-design-principles
cd suricata-check
pip install .
pytest
```

## Preparing the development environment

To install packages required for running tests and linting, run the following command:

```bash
pip install pip-tools
pip-compile --all-extras -o requirements-dev.txt pyproject.toml
pip install -r requirements-dev.txt
```

## Running tests

If you wish to run the majority of the tests whilst skipping the slow integration tests on large third-party rulesets, use the following command:

```bash
pytest
```

To run the slower integration tests at the end of your development cycle, use the following command instead:

```bash
pytest -m "slow" -k "not train"
```

## Training new models

To run the train new ML models (i.e., `PrincipleMLChecker`) at the end of your development cycle in case you modified this pipeline, delete the `.pkl` files corresponding to the saved model(s) and run the following command:

```bash
pytest -m "slow" -k "train" --cov-fail-under=0
```

## Linting

To automatically fix some linting issues and check for remaining issues, run the following commands:

```bash
black .
ruff check . --fix
pyright
```

### Markdownlint

If you made changes to `.md` file and want to lint them locally, you have to install `markdownlint` using `npm`.

```bash
npm install -g markdownlint-cli2
```

Now you can lint markdown files using to automatically detect all issues and fix some:

```bash
markdownlint-cli2 --fix "**/*.md"
```

## Docs

To automatically generate the documentation from the code, run the following commands:

```bash
./docs/make.bat clean
./docs/make.bat html
```

To locally view the docs, run the following command:

```bash
python -m http.server -b localhost -d docs/_build/html 8000
```

and inspect the docs at `localhost:8000`

## Pull requests

When you create a pull request (PR), several checks are automatically run. These include some basic code style checks, as well as running all non-slow tests. PRs that do not pass these checks will not be merged. Additionally, PRs will undergo atleast one round of feedback before merging and require approval of atleast one contributor.
