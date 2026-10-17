# Asservat console

Production React/TypeScript source, separate from the synthetic `design/ui`
prototype. The current implementation provides session handling and a reusable
protected-view boundary. Investigation services and public deployment are still
being composed; the signed-in page reports that limit.

From the repository root:

```sh
make console-install
make console-check console-build
make console-browser-check
```

The browser gate requires a locally installed Playwright browser, or
`ASSERVAT_CHROMIUM` pointing to a compatible Chromium executable. It uses an owned
loopback HTTPS fixture with synthetic identity facts and actual Go HTTP handlers.
It is not a development authentication mode in the product. Runtime installation
will package `web/dist` beside the Go binary; no Node service is required.

Run `npm run generate` here after reviewing canonical authentication OpenAPI
changes. Generated types and standalone validators are checked in; `npm run
contracts` rejects drift. Installation uses the committed lock and disables
dependency lifecycle scripts. Source maps are not included in the build.

See [the runtime contract](../docs/architecture/console-runtime.md) for request,
cache, cancellation, CSP and qualification boundaries.
