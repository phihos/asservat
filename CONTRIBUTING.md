# Contributing

Asservat is licensed under the [Apache License 2.0](LICENSE). Contributions are
accepted under the same licence (section 5 of the licence).

## Sign off your commits

Every commit must carry a `Signed-off-by` line certifying the
[Developer Certificate of Origin](https://developercertificate.org/): you wrote
the change or otherwise have the right to submit it under the project's licence.

```sh
git commit -s
```

Use your real name or a stable public identity. There is no separate contributor
licence agreement.

## Before opening a pull request

Read the [project guide](docs/project-guide.md) and the specification for the area
you change. Behavior changes update the relevant `specs/` and, for consequential
decisions, add a record under `docs/decisions/`. Tests use synthetic data only.
CI runs the gates in [validation](docs/validation.md) on every pull request.
