# htmltrust-hugo

Spec-conformant HTMLTrust content signing for [Hugo](https://gohugo.io/) static sites.

## Project status and compatibility

This repository is the Hugo module and post-build signer reference
implementation. It is usable for sites that opt into the `signed-section`
partial. The CLI signs generated HTML; it does not manage keys, publish DID
documents, or verify a site in the browser.

The checkout currently builds with Go 1.25 and Hugo 0.128 or newer. Its Go
module pins the canonicalization binding to the immutable commit
`5e51040dcaaf50935e245702bdefbc18a1d542ce`, the current HTMLTrust
canonicalization v1 release candidate.

| Component | Version or commit | Role |
|---|---|---|
| `htmltrust-hugo` | pin a reviewed commit from this repository | Hugo partial and signer |
| Go canonicalization binding | `v0.0.0-20260828102949-5e51040dcaaf` | HTMLTrust v1 Unicode, HTML, claims, and URL canonicalization |
| Hugo | `0.128.0` or newer | Static-site build |
| Go | `1.25` or newer | CLI build and tests |

Pin this module and its canonicalization dependency to reviewed commits when
reproducing a release. The dependency is currently a v1 release candidate;
avoid branch names and moving version selectors in production builds.

This module adds signatures to Hugo sites whose templates already identify the
content to sign. It ships a Hugo partial and a post-build signer.

1. **A Hugo Module** with a `<signed-section>` partial you drop into your templates. Build-time only emits the structural element with claims metadata.
2. **A companion Go CLI** (`htmltrust-sign`) you run after `hugo build`. It applies the [HTMLTrust canonicalization profile](https://github.com/HTMLTrust/htmltrust-canonicalization), computes the SHA-256 hashes, builds the v1 JSON payload, and signs it with Ed25519. It rewrites every `<signed-section>` in `public/` with the profile, scope, key, algorithm, content hash, and signature attributes.

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
dependency resolves to the v1 commit shown above.

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

> **Note on claim casing.** Hugo lowercases frontmatter keys when parsing. To avoid surprises, use lowercase-with-hyphens for claim names (`content-type`, not `ContentType`). The hash is case-sensitive — what you write is what gets signed.

### 4. Set site-level defaults (optional)

```toml
[params.htmltrust]
  keyid     = "did:web:jason-grey.com"
  algorithm = "ed25519"
```

These show up as defaults on the placeholder; the CLI overrides them via flags at sign time.

## Sign at build time

```sh
hugo --minify

  go install github.com/HTMLTrust/htmltrust-hugo/cmd/htmltrust-sign@<reviewed-commit>

htmltrust-sign \
  --dir public \
  --keyid did:web:jason-grey.com \
  --domain https://www.example.com \
  --scope url \
  --keyfile $HOME/.htmltrust/signing-key.pem
```

Or with the private key in an env var (typical for CI):

```sh
export HTMLTRUST_SIGNING_KEY="$(cat path/to/key.pem)"
htmltrust-sign --dir public --keyid did:web:jason-grey.com --domain https://www.example.com
```

### Flags

| Flag | Default | Notes |
|---|---|---|
| `--dir` | `public` | Directory of built HTML files to scan. |
| `--keyid` | _(required)_ | Identifier embedded in each `<signed-section>` and used by verifiers to fetch your public key. Standard form is `did:web:<host>`. |
| `--domain` | _(required)_ | HTTPS publication origin, serialized as `https://host[:port]`. Bare hosts are normalized to `https://host`. Paths, queries, fragments, and credentials are rejected. |
| `--algorithm` | `ed25519` | Only `ed25519` is supported in this revision. |
| `--scope` | `url` | Binds the signature to the page URL; `origin` permits same-origin reuse. |
| `--keyfile` | _none_ | PEM-encoded PKCS#8 Ed25519 private key. Falls back to `HTMLTRUST_SIGNING_KEY` env var if unset. |
| `--dry-run` | `false` | Report what would change without writing. |
| `-v` | `false` | Print each file processed. |

## What gets emitted

After `hugo --minify` + `htmltrust-sign`:

```html
<signed-section
    content-hash="sha256:KHcklrJyVZs/510AaHHMb2HYj9A0XzM+ELKGFV8FrIk"
    signature="0V7YTUfv0z2w9xhuPik9rBWPILZ9D5NHmF3ygqRlThHEPpjr55LoJ4hCddDL0FNn7wuqinfBK8OmCJIoDr7MCQ"
    keyid="did:web:jason-grey.com"
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

Keep `signing-key.pem` private — in a password manager, a KMS, or a CI secret. **Never commit it.**

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

HTMLTrust is an idea I (Jason Grey) have been chewing on since 2024. I'm not an academic — I'm an engineer with a day job and a family — so the spec, the reference implementations, and most of this prose have been written with significant help from AI tools acting as research assistant, technical writer, and pair programmer. I wrote the original architectural sketches and reviewed every line; the assistants filled in the gaps and saved me from re-typing the same explanation for the hundredth time.

**Contributions are welcome — human or AI-assisted, doesn't matter to me.** What matters is whether the code, the spec text, or the conformance vectors move the project forward. Open a PR.

What this project is **not** a forum for:

- Debates about whether AI should be used to write code or specifications.
- Opinions on who is or isn't trustworthy on the web.
- Politics, religion, professional practice, or personal philosophy.

HTMLTrust is a mechanism — a way for *anyone* to sign content they publish and for *anyone* to decide whom they trust, on their own terms. The project takes no position on what the right answers are; it just provides the tools. If you want to debate the answers, there are entire continents of the internet better suited to it.

If this work is useful to you and you'd like to support it, see [GitHub Sponsors](https://github.com/sponsors/jt55401) or the other channels in [`.github/FUNDING.yml`](.github/FUNDING.yml).
