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

Read the [design](docs/design.md). Behavior changes update it in the same pull
request. Tests use synthetic data only.

## Run the checks

Asservat is written in Go and stores its state in PostgreSQL.

```sh
gofmt -l . && go vet ./...
ASSERVAT_TEST_DSN=postgres://postgres:pw@127.0.0.1:5432/postgres go test -race ./...
helm lint charts/asservat
test/e2e/run.sh   # creates and removes two kind clusters
```

CI runs the same checks on every pull request.
