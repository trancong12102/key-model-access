# CPA Key Model Access plugin

A native dynamic-library plugin for CLIProxyAPI (CPA). CPA keeps doing downstream authentication
with its top-level `api-keys`; this plugin only reads the `Metadata.caller_scope` CPA provides to
its RequestInterceptor and enforces model allow/deny rules for **API keys that already exist in
CPA**.

> This is a fork of [LTbinglingfeng/key-model-access](https://github.com/LTbinglingfeng/key-model-access)
> v0.1.3. Its only changes: the settings UI is in English, and CI no longer builds FreeBSD
> (the 14.3-RELEASE base archive it downloaded is gone). Releases are tagged `v<upstream>-en`.

> `0.1.x` is a breaking pre-1 minor relative to `0.0.2`. The v1 policy format is incompatible;
> follow the migration steps below before upgrading from 0.0.2.

## Scope

- Creating, deleting, storing and authenticating API keys is entirely CPA's built-in provider's job.
- The plugin does not create, delete or store raw keys and is not an authentication provider. The
  Web UI only reads the existing CPA keys to associate scopes with them.
- After CPA authenticates a request it puts a stable `caller_scope` into the RequestInterceptor
  metadata; the plugin uses that scope alone to look up the model policy.
- Existing keys without a policy may use every model.
- With a policy: `deny_models` wins; a non-empty `allow_models` is an allowlist; an empty
  `allow_models` allows everything not denied.
- `*` matches any run of characters (including `/`), `?` matches one character; matching is
  case-sensitive.
- The model name is CPA's `RequestedModel`, or `Model` when that is empty.

The plugin is not an authentication layer. Whether an unknown or invalid key is accepted is decided
by CPA's top-level `api-keys`; never put a key only in the plugin config.

## Compatibility

- CLIProxyAPI **v7.2.103 or newer**.
- CPA plugin RPC schema 2, which lets a RequestInterceptor return a structured `403`.
- A CGO build of CPA with dynamic plugin support; building needs Go 1.24, a C compiler and
  `CGO_ENABLED=1`.
- Any Management API response carrying the header `X-CPA-SUPPORT-PLUGIN: 1` confirms the CPA binary
  supports plugins.

## Install

### 1. Build or install the dynamic library

```bash
make test
make build
make package
```

On macOS arm64 with the default version this produces:

```text
dist/key-model-access.dylib
dist/key-model-access_0.1.3-en_darwin_arm64.zip
dist/key-model-access_0.1.3-en_darwin_arm64.zip.sha256
```

Library extensions:

- macOS: `key-model-access.dylib`
- Linux / FreeBSD: `key-model-access.so`
- Windows: `key-model-access.dll`

Install into the local CPA platform directory:

```bash
make install CPA_DIR=/path/to/CLIProxyAPI
```

or copy it by hand to:

```text
<CPA>/plugins/<GOOS>/<GOARCH>/key-model-access.<ext>
```

The library's base ID must be `key-model-access` and match `plugins.configs.key-model-access`; the
`key-model-access-v<version>.<ext>` suffix CPA supports also works. Build `c-shared` artifacts on the
target system; setting `GOOS` for an ordinary cross-compile is not enough.

Build parameters can be overridden:

```bash
make build GOOS=darwin GOARCH=arm64 BUILD_DIR=/path/to/plugins/darwin/arm64
make package VERSION=0.1.3-en
```

### 2. Configure CPA keys and an empty v2 policy

Merge [`config.example.yaml`](./config.example.yaml) into CPA's `config.yaml`. For the first start,
use an inline empty policy rather than pointing at a file that doesn't exist yet:

```yaml
api-keys:
  - "replace-with-a-real-api-key"

plugins:
  enabled: true
  dir: "plugins"
  configs:
    key-model-access:
      enabled: true
      priority: 100
      version: 2
      policies: []
```

In this state CPA's top-level `api-keys` still authenticate, and every authenticated key may use
every model. Then, in a maintenance window, use the Web UI to create v2 policies for the keys that
need limits.

### 3. Default persistence

The first time the Web UI opens, it reads the actual `plugins.dir` through CPA's official
Management API and creates:

```text
<plugins.dir>/key-model-access/config.toml
```

It then writes that path into `plugins.configs.key-model-access.policy_file`, which CPA saves before
reconfiguring the plugin. Initialisation keeps the currently effective inline v2 policies; if the
target file already exists it is validated and reused, never overwritten. Later UI edits are saved
atomically with mode `0600` and survive CPA or plugin restarts.

The Web UI discovers the directory, rather than the library guessing its own path, because CPA's
plugin ABI does not pass `plugins.dir`, the directory is configurable, and Windows loads DLLs from a
temporary shadow copy.

To keep policies somewhere else, configure an existing YAML or TOML file explicitly:

```yaml
policy_file: "config/key-model-access-policies.yaml"
```

An explicit target must already exist and be a valid v2 document; if it is missing or invalid the
plugin fails closed. Relative paths are resolved from CPA's working directory. Once `policy_file` is
set, that file is the authoritative policy source and inline `version` / `policies` no longer apply.

Docker deployments must persist the whole plugin directory **writable**:

```yaml
volumes:
  - ./plugins:/CLIProxyAPI/plugins
```

If you use another policy directory, persist that whole directory too. Don't bind-mount a single
policy file: the plugin saves through a temporary file in the same directory, `fsync` and `rename`,
which a single-file mount usually prevents. If the plugin directory is read-only or CPA's config
file is not writable, automatic initialisation reports an error in the UI and the plugin keeps
running in memory-only mode.

## Upgrading from 0.0.2 / v1

v1 key identities and v2 `caller_scope` are different designs, so old policies cannot be converted
in place. Before upgrading:

1. In a controlled maintenance window, stop external traffic and back up the CPA config and the old
   policies.
2. Make sure every **raw key** still in use is kept in, or moved to, CPA's top-level `api-keys`. A
   credential known only by its old `key_sha256` cannot be restored into CPA; create a replacement
   key and update its clients.
3. Remove the v1 fields from the plugin config and old policies: `keys`, `default_action`,
   `models_endpoint`, `allow_query_keys`.
4. Remove any `policy_file` pointing at a v1 file and switch to inline `version: 2`,
   `policies: []`. Don't let 0.1.0 read a v1 file; it rejects v1 and fails closed on first start.
5. Install 0.1.0 and restart CPA; first confirm the top-level keys still authenticate normally.
6. Open the Web UI, load the current CPA keys and **recreate the v2 policies** for the keys that
   need limits.
7. Let the new Web UI create and configure the default `config.toml`, then re-check and save. With
   an explicit custom path, create a valid v2 file first.

An empty v2 policy allows every authenticated key to call every model the interceptor covers. Keep
external traffic off during migration until the limiting policies are recreated and verified.

## Web UI

With the plugin enabled, open:

```text
http://<CPA_HOST>:<CPA_PORT>/v0/resource/plugins/key-model-access/settings
```

The page registers as "Model Access" in CPAMC management UIs that support plugin resource menus.
It does not ask for the Management Key: it reuses, read-only, the same-origin `cli-proxy-auth`
session CPAMC already saved, and follows CPAMC's theme. Automatic connection requires:

- the CPAMC page and the CPA API on the same origin (scheme, host and port);
- "Remember password" enabled when logging in to CPAMC, so the Management Key is in CPAMC's
  Local Storage session.

Otherwise the page asks you to go back to CPAMC and fix the session; it offers no manual key entry.
Once connected the UI:

1. if nothing is persisted yet, reads CPA's `plugins_dir`, creates
   `<plugins.dir>/key-model-access/config.toml`, then writes `policy_file` through CPA's official
   plugin config API;
2. calls `GET /v0/management/api-keys` to read CPA's current top-level keys, read-only;
3. computes each key's `caller_scope` in the browser, using CPA's rule;
4. reads `GET /v1/models` with the first CPA API key to build a searchable, multi-select model
   catalogue;
5. reads the plugin's v2 policies and matches them to scopes;
6. lets you edit and save `allow_models` and `deny_models` with the picker. The picker offers exact
   models, all models `*`, and wildcards for common model families it recognises in the catalogue;
   other existing custom wildcards are kept and shown with their catalogue matches.

The UI never creates, changes or deletes CPA keys and never writes to `/v0/management/api-keys`.
Key lifecycle stays with CPA's config or CPA's own management features. The UI compares the CPA key
set before and after saving policies: a change before saving aborts and asks for a refresh; a change
after saving warns immediately that the new key is currently allowed everything. The two requests
are not a transaction, so key changes and policy saves should be serialised by your operating
process. Old scopes that no longer match a current key are flagged as stale policies and kept on
save rather than silently deleted.

### UI security boundaries

- `/v0/management/api-keys` returns raw keys to a browser holding Management authentication. The UI
  keeps them in JavaScript only briefly, to compute scopes and to read the model catalogue with the
  first key, then clears the temporary array as best it can. Raw keys are never written to the DOM,
  Local Storage, Session Storage, URLs or the plugin policy.
- Whether the Management Key is persisted is CPAMC's decision. The plugin only parses CPAMC's
  same-origin session, read-only, uses it in its own JavaScript memory, and never copies it or
  writes it to storage again.
- CPAMC's current browser-side storage is reversible obfuscation, not a security boundary.
  Same-origin pages, browser extensions and malware on the same machine are all inside the trust
  boundary.
- The page follows CPAMC's theme read-only and keeps no theme preference of its own.
- Page responses use a random-nonce CSP, `frame-ancestors 'self'`, `X-Frame-Options: SAMEORIGIN`,
  `form-action 'none'` and `Cache-Control: no-store`.
- Use HTTPS, restrict network reachability of the Management API, and open the UI only on trusted
  browsers and devices.
- The page shell contains no keys or policy data; every Management API data request is protected by
  the CPA Management Key.

## Policy schema v2

A v2 document has only `version` and `policies` at the top level. Each policy has only:

- `caller_scope`: the 64-hex-character scope CPA derives for an existing API key. Let the Web UI
  generate and associate it; it is neither the raw key nor the old `key_sha256`.
- `allow_models`: array of allow patterns.
- `deny_models`: array of deny patterns.

Don't guess or reuse old hashes by hand; use the UI to load CPA's current keys and generate the
right scope.

### YAML

See [`policies.example.yaml`](./policies.example.yaml):

```yaml
version: 2
policies:
  - caller_scope: "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a"
    allow_models:
      - "gpt-5*"
      - "claude-sonnet-*"
    deny_models:
      - "*-preview"
```

### TOML

The generated `config.toml` uses the same schema:

```toml
version = 2

[[policies]]
caller_scope = "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a"
allow_models = ["gpt-5*", "claude-sonnet-*"]
deny_models = ["*-preview"]
```

### JSON

The Management API PUT body uses the same schema:

```json
{
  "version": 2,
  "policies": [
    {
      "caller_scope": "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a",
      "allow_models": ["gpt-5*", "claude-sonnet-*"],
      "deny_models": ["*-preview"]
    }
  ]
}
```

Matching:

1. Key has no policy: every model is allowed.
2. Any `deny_models` match: refused; this takes precedence over everything.
3. Non-empty `allow_models`: allowed only on an allow match with no deny match.
4. Empty `allow_models`: everything not denied is allowed.
5. Empty allow and deny lists equal allow-all; the UI normally writes no policy for such a key.

YAML, TOML and JSON all strictly reject unknown fields, duplicate `caller_scope` values and scopes
that are not 64 hex characters. Old identity fields such as `key`, `key_sha256`, `id` and `enabled`
are not accepted.

## Management API

The plugin routes are protected by the CPA Management Key:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v0/management/plugins/key-model-access/status` | Version, policy source, persistence and fail-closed state; no scopes |
| `GET` | `/v0/management/plugins/key-model-access/policies` | The full v2 policy document and its revision |
| `PUT` | `/v0/management/plugins/key-model-access/policies` | Atomically replace all policies with JSON |
| `POST` | `/v0/management/plugins/key-model-access/reload` | Reload from the configured `policy_file` |
| `POST` | `/v0/management/plugins/key-model-access/initialize-storage` | Create or validate the default `config.toml` under the given CPA plugin root |

The UI also calls CPA's own `GET /v0/management/plugins` to find the real plugin directory, and
`PATCH /v0/management/plugins/key-model-access/config` to write `policy_file` only. It calls
`GET /v0/management/api-keys` read-only; that endpoint returns CPA keys to authorised management
clients, so never log or forward its response.

Set variables and check status:

```bash
export CPA_URL=http://127.0.0.1:8317
export CPA_MANAGEMENT_KEY='your-management-key'

curl -sS \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  "$CPA_URL/v0/management/plugins/key-model-access/status"
```

Read the policies and keep the `ETag: "rev-N"` from the response:

```bash
curl -i \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  "$CPA_URL/v0/management/plugins/key-model-access/policies"
```

Replace all policies:

```bash
curl -sS -X PUT \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "rev-N"' \
  "$CPA_URL/v0/management/plugins/key-model-access/policies" \
  --data-binary @- <<'JSON'
{
  "version": 2,
  "policies": [
    {
      "caller_scope": "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a",
      "allow_models": ["gpt-5*"],
      "deny_models": ["*-preview"]
    }
  ]
}
JSON
```

`GET policies` returns the revision and an ETag. Sending `If-Match` prevents overwriting concurrent
changes; a revision mismatch returns `412`. For compatibility the backend still accepts a PUT
without `If-Match`, but that is not recommended.

With `policy_file` configured, a PUT is persisted atomically with mode `0600`; the Web UI sets this
up automatically the first time it opens. If automatic initialisation failed or the UI has not been
opened yet, a PUT without a configured file only updates memory. Reload returns `409` when no file
is configured; with an invalid file it keeps the last valid policy and reports the error.

## Verification

List the plugins CPA registered:

```bash
curl -sS \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  "$CPA_URL/v0/management/plugins"
```

The status should include at least:

```json
{
  "version": "0.1.3-en",
  "schema_version": 2,
  "auth_mode": "cpa_builtin_api_keys",
  "identity_source": "Metadata.caller_scope",
  "unconfigured_key_action": "allow",
  "fail_closed": false
}
```

Test allowed and refused models with the same top-level CPA key:

```bash
# should be allowed
curl -i "$CPA_URL/v1/chat/completions" \
  -H 'Authorization: Bearer your-existing-cpa-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}'

# with a policy allowing only gpt-5*, the plugin returns a structured 403 and the request never
# reaches the upstream
curl -i "$CPA_URL/v1/chat/completions" \
  -H 'Authorization: Bearer your-existing-cpa-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"claude-sonnet","messages":[{"role":"user","content":"hi"}]}'

# a key not in CPA's top-level api-keys is refused by CPA's auth layer, not by this plugin
curl -i "$CPA_URL/v1/chat/completions" \
  -H 'Authorization: Bearer unknown-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}'
```

Local quality checks:

```bash
gofmt -w types.go
go test ./...
go vet ./...
git diff --check
```

## Current limits

CPA's RequestInterceptor does not yet fully cover these paths or flows:

- `/v1/models`
- `alpha/search`
- Codex Live (including its realtime/sideband flows)

So don't rely on this plugin for complete per-key model isolation there; `/v1/models` may return
CPA's global model list. For requests that do reach the RequestInterceptor, a key with a policy but
no model name fails closed; keys without a policy are still allowed by default. If those uncovered
entry points must be restricted, disable or limit them in CPA/upstream provider config, a reverse
proxy or the network layer until CPA provides full hook coverage.

Also:

- The plugin only constrains requests that reach the RequestInterceptor with a recognisable model
  name; it doesn't filter CPA's global model catalogue.
- When policies exist but CPA provides no `caller_scope`, covered requests fail closed; with a
  completely empty policy, requests without a scope are not refused by the plugin, and
  authentication stays with CPA.
- An invalid config, an old v1 file or a missing `policy_file` on first load makes the plugin fail
  closed; later invalid hot reloads keep the last valid snapshot.
- Policy changes affect only later requests; requests already running upstream are not interrupted.

## Security notes

- Native plugins run inside the CPA process; install only trusted builds.
- Raw API keys belong only in CPA's top-level `api-keys`; never put them in the plugin config, the
  policy file or a PUT body.
- `caller_scope` is a stable pseudonymous identifier and still sensitive management data; don't
  publish policy responses or files.
- Management API responses set `Cache-Control: no-store`; limit Management Key access and rotate it
  regularly.
- The default policy lives at `<plugins.dir>/key-model-access/config.toml`; restrict the plugin
  directory's permissions and include this plugin's subdirectory in secure backups. An explicit
  `policy_file` should likewise be readable only by the CPA process user.
- No policy means allow-all. After adding a CPA key, refresh the UI and configure its limits promptly;
  if new keys must be deny-by-default, do that in outer automation or at the network boundary.

## Build and release artifacts

The GitHub Actions workflow [`.github/workflows/build.yml`](./.github/workflows/build.yml) runs tests,
builds, and publishes the release format. For version 0.1.3-en the archives are:

```text
key-model-access_0.1.3-en_<goos>_<goarch>.zip
checksums.txt
```

Build the current platform's archive and the aggregate checksum file locally:

```bash
make checksums VERSION=0.1.3-en
```

Release by pushing a tag:

```bash
git tag -a v0.1.3-en -m "Release v0.1.3-en"
git push origin v0.1.3-en
```

## Upstream documentation

- https://help.router-for.me/plugin/development
- https://help.router-for.me/plugin/request-interceptor
- https://help.router-for.me/plugin/management-api
- https://github.com/router-for-me/CLIProxyAPI/tree/main/examples/plugin
