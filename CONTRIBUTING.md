# Contributing to tcfig

Contributing to this project is highly appreciated and encouraged, but you will need to follow some guidelines


## Branch policy

All the development happens on the `dev` branch, and not on the `main` branch which is locked to the release code

To branch-off `dev` :

```bash
git checkout dev
git checkout -b <feature/bug124>
```

Then push your PR against `dev`

## Security

All commits are to get GPG-signed before they can be merged into the repo, you can follow GitHub's [onboarding](https://docs.github.com/en/authentication/managing-commit-signature-verification/checking-for-existing-gpg-keys) about this

## Developping environnment

As for the end-user, this project relies on `pipenv` for dependency management

You can install the required dev dependencies with the following commands

```bash
git clone <yourfork>/tcfig.git
cd tcfig
pipenv install --dev
pipenv shell
```

## Code style

Code style is enforced through [pre-commit](https://pre-commit.com/) which in turn will run `autopep8` :

To prepare it, inside the `pipenv` shell :

```bash
pre-commit install
```

## Documentation

Documentation is at the heart of the project, as such, we require a full [docstring](https://sphinx-rtd-tutorial.readthedocs.io/en/latest/docstrings.html) documentation for each function

Helpful in-code clarification comments are also welcome and encouraged

Documentation is served by [read-the-docs](https://readthedocs.org/) using [Sphinx](https://www.sphinx-doc.org/en/master/)

### Note :

If you modified any of the docstrings on the script, you will need to run the following before running the following `sphinx-build` command :

```bash
cd docs
sphinx-apidoc -f -o source/ ..
```
You can build the documentation locally with the following commands :

```bash
cd docs
sphinx-build source output-docs
```
