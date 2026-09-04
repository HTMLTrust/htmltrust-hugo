# htmltrust-hugo

Spec-conformant HTMLTrust content signing for [Hugo](https://gohugo.io/) static sites.

## Project status and compatibility

This repository is the Hugo module and post-build signer reference
implementation. Sites opt into the `signed-section` partial. The CLI signs
generated HTML. Key management, DID publication, and browser verification are
outside this repository.

The checkout currently builds with Go 1.25 and Hugo 0.128 or newer. Its Go
module pins the canonicalization binding to the immutable commit
`760593d4a02e9fffa56dc4d002eb52ab2ade1b49`, the current HTMLTrust
canonicalization v1 release candidate.

| Component | Version or commit | Role |
|---|---|---|
| `htmltrust-hugo` | pin a reviewed commit from this repository | Hugo partial and signer |
| Go canonicalization binding | `v0.0.0-20260828183729-760593d4a02e` | HTMLTrust v1 Unicode, HTML, claims, and URL canonicalization |
| Hugo | `0.128.0` or newer | Static-site build |
| Go | `1.25` or newer | CLI build and tests |

Pin this module and its canonicalization dependency to reviewed commits when
reproducing a release. The dependency is currently a v1 release candidate;
avoid branch names and moving version selectors in production builds.

This module adds signatures to Hugo sites whose templates identify the content
to sign. It ships a Hugo partial and a post-build signer.

1. **A Hugo Module** with a `<signed-section>` partial you drop into your templates. Build-time only emits the structural element with claims metadata.
2. **A companion Go CLI** (`htmltrust-sign`) you run after `hugo build`. It applies the [HTMLTrust canonicalization profile](https://github.com/HTMLTrust/htmltrust-canonicalization), computes the SHA-256 hashes, builds the v1 JSON payload, and signs it with Ed25519. It rewrites every `<signed-section>` in `public/` with the profile, scope, key, algorithm, content hash, and signature attributes.
3. **An offline ceremony CLI** (`htmltrust-key`, optional but recommended) for [period-scoped signing keys](#period-scoped-signing-keys): the online signer holds one short-lived derived key at a time instead of one long-lived key, so a compromise costs one period of content instead of everything ever signed.

## Why two pieces?

The HTMLTrust spec requires Unicode NFKC normalization, structured claims hashing, and cryptographic signatures. Hugo's template engine has none of those: no NFKC, no Ed25519, no PEM parsing. Earlier Hugo-only integrations papered over this by computing a SHA-256 over a crude `replaceRE \s+ " "` canonicalization. That produces hashes that don't match the canonicalization spec, and never produces a real signature.

This module is honest about that split. The partial emits a placeholder that's structurally complete. The CLI does the cryptography.

## Quick start from a clean checkout

```sh
git clone https://github.com/HTMLTrust/htmltrust-hugo.git
cd htmltrust-hugo
go test ./...
go vet ./...
go build ./cmd/htmltrust-sign
go build ./cmd/htmltrust-preflight
go build ./cmd/htmltrust-key
```

The module checkout has no content site to render. In a consuming site, check
the Hugo version and validate a build with:

```sh
hugo version
hugo --minify --destination public
```

To run the optional cross-repository vector check, place the canonicalization
repository beside this checkout under the same parent directory:

```sh
git clone https://github.com/HTMLTrust/htmltrust-canonicalization.git ../htmltrust-canonicalization
go test ./cmd/htmltrust-sign
```

The check reads the shared fixture when that sibling checkout is present. The
normal unit suite remains self-contained.

## Install

### 1. Add the Hugo Module to your site

```toml
# config.toml or hugo.toml
[module]
  [[module.imports]]
    path = "github.com/HTMLTrust/htmltrust-hugo"
```

Initialize the module if you haven't:

```sh
hugo mod init github.com/your-org/your-site
hugo mod get github.com/HTMLTrust/htmltrust-hugo@<reviewed-commit>
```

Run `hugo mod graph` after installation to confirm that the canonicalization
dependency resolves to the reviewed v1 version shown above. Replace every
`<reviewed-commit>` below with a full 40-character SHA that you inspected.
Resolve a branch or tag once, then pin that SHA in the site or CI:

```sh
HUGO_URL=https://github.com/HTMLTrust/htmltrust-hugo.git
HUGO_REF=REPLACE_WITH_REVIEWED_TAG
HUGO_SHA="$(git ls-remote "$HUGO_URL" "refs/tags/$HUGO_REF" | awk 'NR==1 {print $1}')"
test "$HUGO_SHA" && test "${#HUGO_SHA}" -eq 40
hugo mod get "github.com/HTMLTrust/htmltrust-hugo@$HUGO_SHA"
```

### 2. Wire the partial into your content template

In `layouts/_default/single.html` (or wherever you render `.Content`):

```html
{{ partial "htmltrust-signed-section.html" . }}
```

This replaces `{{ .Content }}` for pages that opt in via frontmatter. Pages that don't opt in fall through to plain `.Content`.

### 3. Opt in per page

```yaml
---
title: "My Post"
date: 2026-05-12T20:00:00Z
htmltrust:
  sign: true
  claims:
    content-type: "Article"
    license: "CC-BY-4.0"
    ai-assistance: "None"
---
```

> **Note on claim casing.** Hugo lowercases frontmatter keys when parsing. Use lowercase-with-hyphens for claim names such as `content-type`. The hash is case-sensitive, so the written value is signed.

### 4. Set site-level defaults (optional)

```toml
[params.htmltrust]
  keyid     = "did:web:example.com"
  algorithm = "ed25519"
```

These show up as defaults on the placeholder; the CLI overrides them via flags at sign time.

## Sign at build time

```sh
hugo version
hugo --minify --destination public

  go install github.com/HTMLTrust/htmltrust-hugo/cmd/htmltrust-sign@<reviewed-commit>

htmltrust-sign \
  --dir public \
  --keyid did:web:example.com \
  --domain https://www.example.com \
  --scope url \
  --keyfile $HOME/.htmltrust/signing-key.pem
```

Or with the private key in an env var (typical for CI):

```sh
export HTMLTRUST_SIGNING_KEY="$(cat path/to/key.pem)"
htmltrust-sign --dir public --keyid did:web:example.com --domain https://www.example.com
```

`--domain` accepts either form: a bare host (`www.example.com`) or a full
`https://` origin (`https://www.example.com`) are equivalent; a bare host is
normalized to HTTPS. The two forms appear interchangeably through this
README and the CI example below, matching what the flag actually accepts.

`--keyid` stays the identity, not a period-fragmented keyid, even once you
adopt [period-scoped signing keys](#period-scoped-signing-keys): the signer
resolves the actual `keyid` it embeds -- `did:web:example.com#p3`, or the
bare identity -- itself, by matching the loaded private key against the
identity's DID document. See that section before generating a production
key; period-scoped keys are the recommended setup for anything CI signs.

## Preflight generated pages before publication

Run the preflight adapter after Hugo renders `public/` and before the signer
writes cryptographic attributes:

```sh
hugo version
hugo --minify --destination public
go run ./cmd/htmltrust-preflight \
  --dir public \
  --domain https://www.example.com \
  --strict \
  --json > htmltrust-preflight.json
htmltrust-sign \
  --dir public \
  --keyid did:web:example.com \
  --domain https://www.example.com \
  --keyfile "$HOME/.htmltrust/signing-key.pem"
```

`--domain` is the publication origin. The adapter derives each page URL from
the generated path (`index.html` becomes the directory URL), then resolves
the first `<base href>` in tree order against that final page URL. Later base
elements are ignored. A malformed, `data:`, or `javascript:` first base falls
back to the final page URL. An HTTP or credential-bearing first base remains
the document base, so relative signed URLs fail the HTMLTrust safe-URL check.
Relative `href` and `src` values inside a signed region therefore get the same
base treatment as the signer.

The JSON report contains one result per generated HTML file and one result per
signed region. Each region includes canonical content, canonical claims, a
DOM path, and diagnostics with stable `code`, `hint`, and `context` fields.
Pages without a signed region carry a warning and remain successful, which
allows sites to sign only selected templates. With `--strict`, any failed
signed region exits with status `1`, so CI can stop before publication.

For an installed binary, use the same command after building it:

```sh
go install github.com/HTMLTrust/htmltrust-hugo/cmd/htmltrust-preflight@<reviewed-commit>
htmltrust-preflight --dir public --domain https://www.example.com --strict --json
```

The reusable Go API is in the `preflight` package:

```go
import "github.com/HTMLTrust/htmltrust-hugo/preflight"

report := preflight.PreflightHTML(pageBytes, "https://www.example.com/articles/intro/")
directory, err := preflight.PreflightDirectory("public", "https://www.example.com")
```

Pass `--keyid` (and a key) to also check period-key discovery before
signing runs, without writing anything:

```sh
htmltrust-preflight \
  --dir public \
  --domain https://www.example.com \
  --keyid did:web:example.com \
  --keyfile "$HOME/.htmltrust/signing-key.pem" \
  --ledger https://www.example.com/.well-known/htmltrust-signatures.json \
  --json
```

adds a `"period"` object to the report -- `periodKeyMatched`, `periodIndex`,
`periodsPublishedAhead`, and (only with `--ledger`) `ledgerReplayed`, a count
of signed regions that would replay unchanged. A deploy can gate on any of
these before the real signing step runs; for example, failing the build when
`periodKeyMatched` is `false` catches a rotated secret whose DID document
was never deployed. Omit `--keyid` and the report has no `"period"` member
at all, exactly as before this existed.

### `htmltrust-sign` flags

| Flag | Default | Notes |
|---|---|---|
| `--dir` | `public` | Directory of built HTML files to scan. |
| `--keyid` | _(required)_ | The identity, not a period keyid: `did:web:<host>` (or an HTTPS URL identity). The `keyid` actually embedded is resolved by period discovery below. |
| `--domain` | _(required)_ | HTTPS publication origin, serialized as `https://host[:port]`. Bare hosts are normalized to `https://host`. Paths, queries, fragments, and credentials are rejected. |
| `--algorithm` | `ed25519` | Only `ed25519` is supported in this revision. |
| `--scope` | `url` | Binds the signature to the page URL; `origin` permits same-origin reuse. |
| `--keyfile` | _none_ | PEM-encoded PKCS#8 Ed25519 private key. Falls back to `HTMLTRUST_SIGNING_KEY` env var if unset. |
| `--did-document` | derived from `--keyid` | URL or local path of the identity's DID document. Required if `--keyid` isn't a `did:web` identity. |
| `--ledger-url` | derived from `--domain` | URL or local path of the live signature ledger to seed replay from. |
| `--ledger-out` | `public/.well-known/htmltrust-signatures.json` | Where the merged ledger is written, so it deploys with the site. |
| `--ledger-bootstrap` | `false` | When the ledger has never been published (404), seed it from each page's live signature after verifying it. |
| `--allow-fresh-ledger` | `false` | Start from an empty ledger on any ledger fetch failure, not only a 404. |
| `--allow-mass-resign` | `false` | Proceed even if more than 10 sections and more than 25% of the previous ledger are being re-signed. |
| `--resign-periods` | _none_ | Force fresh signatures for ledger entries in this period range, for example `2-3`. |
| `--dry-run` | `false` | Report what would change without writing (including the ledger). |
| `-v` | `false` | Print each file processed. |

### `htmltrust-preflight` flags

| Flag | Default | Notes |
|---|---|---|
| `--dir` | `public` | Directory of Hugo-generated HTML files. |
| `--domain` | _(required)_ | HTTPS publication origin. Same bare-host-or-URL rule as `--domain` above. |
| `--json` | `false` | Emit the complete machine-readable report as JSON. |
| `--strict` | `false` | Exit `1` when any signed region fails. |
| `--keyid` | _none_ | Identity to check period-key discovery against. Enables `periodKeyMatched`, `periodIndex`, `periodsPublishedAhead`. |
| `--keyfile` | _none_ | PEM-encoded PKCS#8 Ed25519 private key; required with `--keyid`. Falls back to `HTMLTRUST_SIGNING_KEY`. |
| `--did-document` | derived from `--keyid` | Same rule as `htmltrust-sign --did-document`. |
| `--ledger` | _none_ | URL or local path of the signature ledger. Requires `--keyid`. Enables `ledgerReplayed`. |

## What gets emitted

After `hugo --minify` + `htmltrust-sign`:

```html
<signed-section
    content-hash="sha256:KHcklrJyVZs/510AaHHMb2HYj9A0XzM+ELKGFV8FrIk"
    signature="0V7YTUfv0z2w9xhuPik9rBWPILZ9D5NHmF3ygqRlThHEPpjr55LoJ4hCddDL0FNn7wuqinfBK8OmCJIoDr7MCQ"
    keyid="did:web:example.com#p3"
    algorithm="ed25519"
    profile="htmltrust-signature-v1"
    signature-scope="url"
    style="display: block;">
  <meta name="author" content="…">
  <meta name="signed-at" content="2026-05-12T20:00:00Z">
  <meta name="claim:content-type" content="Article">
  <meta name="claim:license" content="CC-BY-4.0">
  …your content…
</signed-section>
```

Hashes and signatures are **unpadded Base64** per spec §2.1.
The alphabet is standard Base64 (`+` and `/`), not base64url.

## Key generation

Generate an Ed25519 keypair (one time, offline):

```sh
openssl genpkey -algorithm ed25519 -out signing-key.pem
openssl pkey -in signing-key.pem -pubout -out signing-key.pub.pem
```

Publish the public key as a `did:web` document at `https://your-domain/.well-known/did.json`:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:your-domain",
  "verificationMethod": [{
    "id": "did:web:your-domain#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:web:your-domain",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----"
  }],
  "assertionMethod": ["did:web:your-domain#key-1"]
}
```

Keep `signing-key.pem` in a password manager, KMS, or CI secret. Never commit it.

This single static key is still supported, but it has one property worth
being explicit about: whoever holds it can forge a valid signature for
anything, forever, until you notice and revoke it. The next section is the
recommended replacement.

## Period-scoped signing keys

`cmd/htmltrust-key` is the offline ceremony CLI for period-scoped signing
keys (spec draft §9.10, scheme `htmltrust-period-v1`). Instead of one
long-lived private key, an identity keeps a 32-byte master seed offline and
puts exactly one derived Ed25519 key on the online signer at a time -- the
key for period *N*. Its public half is published in the identity's DID
document in advance, so a rollover is a single secret write and nothing
else. A signature's `keyid` names the period it was made under
(`did:web:example.com#p3`); a thief who takes the online signer during
period *c* holds nothing that can forge a signature for any other period,
and every signature made before the theft stays valid without a clock,
timestamp authority, log, or witness. `htmltrust-sign` resolves this keyid
itself (see `--did-document` above); you never type a period fragment by
hand.

Run every `htmltrust-key` command below on an offline machine. It writes no
private key anywhere it wasn't explicitly asked to: `init` writes the
master and the revocation anchor key to one age-encrypted file and nothing
else; `derive` prints or writes exactly the one period's key you asked for.

```sh
go install github.com/HTMLTrust/htmltrust-hugo/cmd/htmltrust-key@<reviewed-commit>
```

### Recommendation: the signing job cannot write the identity origin

Serve the DID document from an origin the CI job that holds the online
signing key cannot write to. If the same pipeline that signs content also
deploys `did.json`, a compromised runner is an origin compromise: the
attacker can rewrite the DID document to cover their tracks, not just sign
forged content. Two separate deployments (the signed site, and the identity
origin serving `did.json` and the revocation list) turn "the CI secret was
stolen" back into "one period's content is at risk," which is the whole
point of adopting period keys in the first place.

### Setup (once, on the offline machine)

```sh
htmltrust-key init --identity did:web:example.com \
  --did-document https://example.com/.well-known/did.json \
  --anchor-key legacy-key-1.pem
```

Reading a served document at `--did-document` migrates an existing
single-key identity: the existing key becomes the anchor (`#key-1`, kept
byte-identical and first), and `--anchor-key` is its private key, imported
as the offline revocation-signing key and then deleted from disk. Omit
`--did-document` for a brand new identity; `init` generates a fresh anchor
(`#rev`) instead. Either way, `init` derives 12 period public keys ahead and
writes `.htmltrust/identity.json` (public; safe to commit) and
`.htmltrust/identity.secret.age` (the encrypted master and anchor key;
`init` refuses to proceed unless it's git-ignored). Back up that file and
its passphrase together, somewhere durable, before anything else -- `init`
prints that reminder first because it's the one step people skip.

Deploy the rendered document, confirm it matches, and deliver the first
period key to CI:

```sh
htmltrust-key did render --out static/.well-known/did.json
# deploy static/.well-known/did.json to the identity origin
htmltrust-key did check --did-document https://example.com/.well-known/did.json
htmltrust-key derive --period 1 | gh secret set HTMLTRUST_SIGNING_KEY --repo your-org/your-site
```

### Monthly rollover

One command, one secret write:

```sh
htmltrust-key derive --period 2 | gh secret set HTMLTRUST_SIGNING_KEY --repo your-org/your-site
```

The next build discovers `#p2` automatically (its public key was already
published), signs under it, and -- with the ledger enabled -- replays every
section that hasn't changed. GitHub keeps no secret history, so the
previous period's key is gone from the online tier the moment the secret is
replaced; that deletion is the entire security property. Nothing about the
DID document changes on a routine rollover.

### Yearly

```sh
htmltrust-key extend --ahead 12
htmltrust-key did render --out static/.well-known/did.json
# deploy static/.well-known/did.json
htmltrust-key did check --did-document https://example.com/.well-known/did.json
```

`extend` publishes more period public keys without touching any private
key. Twelve periods ahead on a monthly schedule means the identity origin
needs a deploy about once a year.

### Compromise

If the online signer (CI secret, server, laptop keyring) was stolen during
period *c*:

```sh
htmltrust-key revoke --from c --to $((c + 1))
# deploy the updated static/.well-known/did.json and the revocation list
htmltrust-key derive --period $((c + 1)) | gh secret set HTMLTRUST_SIGNING_KEY --repo your-org/your-site
```

Every signature made under a period before *c* stays valid on every
period-aware verifier; the thief's stolen key cannot forge a signature
under any other period, because the period is inside the signed bytes. If
the compromise date is uncertain by one rollover, strike from `c - 1`
instead. If the offline master itself was stolen (not just the online
key), strike every period published so far and continue under a new master
with `htmltrust-key rekey`. If the anchor key was stolen, rotate it with
`htmltrust-key revoke --anchor <fragment>`, which inserts a replacement
anchor and re-signs the revocation list under it; legacy (pre-period)
signatures stop verifying from that point on, which is the correct outcome
for a stolen legacy key. `htmltrust-key status` and `htmltrust-key recover`
help when local state is stale or lost; see each command's `-h` output.

### Command reference

| Command | Purpose |
|---|---|
| `init` | Start a period-scoped identity (migrated or fresh). |
| `derive --period N` | Print or write one period's private key. |
| `did render` | Render the DID document from local state. |
| `did check` | Compare the served document against local state. |
| `status` | Report derivation, publication, and live signed-page state. |
| `extend` | Publish more period public keys ahead. |
| `revoke` | Strike a period range, or rotate the anchor key. |
| `rekey` | Replace the master after a suspected compromise. |
| `recover` | Rebuild local state from a served DID document. |
| `list sign` | Sign a hand-edited revocation list with the anchor key. |

### The signature ledger

`htmltrust-sign` writes a signature ledger (`--ledger-url`, `--ledger-out`;
see the flags table above) that is deployed with the site and read back on
the next build. Without it, a routine rollover re-signs every section under
the new period, so striking a later-compromised period would invalidate
every third-party capture of the whole site made during it, even the parts
that never changed. With it, only sections that actually changed during a
struck period are affected; everything else replays its original signature
and `signed-at`. The ledger is an optimisation of loss; the security
property does not depend on it -- a site that never enables the ledger is
exactly as secure as one that does, it just loses more on a compromise.

## CI integration (GitHub Actions example)

```yaml
- name: Setup Go
  uses: actions/setup-go@v5
  with:
    go-version: '1.25'

- name: Install htmltrust-sign
  run: go install github.com/HTMLTrust/htmltrust-hugo/cmd/htmltrust-sign@<reviewed-commit>

- name: Sign content
  env:
    HTMLTRUST_SIGNING_KEY: ${{ secrets.HTMLTRUST_SIGNING_KEY }}
  run: |
    htmltrust-sign \
      --dir public \
      --keyid did:web:example.com \
      --domain https://www.example.com
```

With [period-scoped keys](#period-scoped-signing-keys), `HTMLTRUST_SIGNING_KEY`
holds one period's private key (from `htmltrust-key derive`) instead of the
one long-lived key, and `--keyid` stays the bare identity; add
`--did-document` if it isn't served at the default `did:web` location, and
`--ledger-url`/`--ledger-out` to enable the signature ledger (their
defaults, derived from `--domain` and `--dir`, are usually enough). This
job needs no write access to wherever `did.json` is served -- see the
recommendation in that section.

## How it works (internals)

1. The Hugo partial wraps `.Content` in a `<signed-section>` element with empty `content-hash` and `signature` attributes and a `data-htmltrust-placeholder="true"` marker. Inner `<meta>` tags carry author, signed-at, and claims.
2. After `hugo build`, the CLI walks every `*.html` file in `--dir` using `golang.org/x/net/html`.
3. For each `<signed-section>` found, it:
   1. Reads every direct child `<meta name="..." content="...">` claim, including `author`, `signed-at`, and `claim:*` entries.
   2. Renders the inner HTML (everything between the tags) and canonicalizes signed content locally using the same Unicode normalization rules as [htmltrust-canonicalization/go](https://github.com/HTMLTrust/htmltrust-canonicalization). Direct child claim `<meta>` elements and excluded elements are omitted from content, while signed semantic attributes `href`, `src`, `alt`, and `aria-label` are included.
   3. Computes `content-hash = "sha256:" + RawStdBase64(sha256(canonical_text))`.
   4. Serializes the claims with the v1 escaping rules as sorted `name:content\n` records and hashes them the same way.
   5. Builds the RFC 8785 JSON signing payload with `canonicalize.BuildSigningPayloadV1`, binding the page URL and selected scope.
   6. Signs the payload with the Ed25519 private key.
   7. Rewrites the v1 profile, scope, and cryptographic attributes and removes the placeholder marker.

## Spec conformance

- **Canonicalization:** uses [htmltrust-canonicalization/go](https://github.com/HTMLTrust/htmltrust-canonicalization) for Unicode text normalization and local DOM walking for the current signed semantic attribute and direct-child claim rules.
- **Hash + signature encoding:** canonical unpadded standard Base64 (`base64.RawStdEncoding`).
- **Signing payload:** RFC 8785 canonical JSON from `BuildSigningPayloadV1`, with URL or origin location derived from the page URL.
- **Claim coverage:** every direct child `<meta name content>` claim is signed, including `author`, `signed-at`, and `claim:*`.
- **Semantic attribute coverage:** `href`, `src`, `alt`, and `aria-label` on included descendants contribute to the content hash.
- **Required attributes:** v1 `profile`, `signature-scope`, `keyid`, `algorithm`, `content-hash`, and `signature` are emitted on every signed section.

Verification against this signer's output is round-tripped against `canonicalize.VerifySignature` in the test suite.

## License


This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0). You may use, modify, and share the software for any noncommercial purpose with attribution. Commercial use requires a separate agreement with the licensor.

## Origin & Contributions

HTMLTrust is an idea I (Jason Grey) have been developing since 2024. The spec, reference implementations, and much of this prose were written with help from AI tools. I wrote the original architectural sketches and reviewed the result.

**Contributions are welcome, whether human or AI-assisted.** Open a PR with code, spec text, or conformance vectors that move the project forward.

What this project is **not** a forum for:

- Debates about whether AI should be used to write code or specifications.
- Opinions on who is or isn't trustworthy on the web.
- Politics, religion, professional practice, or personal philosophy.

HTMLTrust is a mechanism for signing published content and letting each reader choose whom to trust. The project provides the tools and does not prescribe those trust decisions.

If this work is useful to you and you'd like to support it, see [GitHub Sponsors](https://github.com/sponsors/jt55401) or the other channels in [`.github/FUNDING.yml`](.github/FUNDING.yml).
