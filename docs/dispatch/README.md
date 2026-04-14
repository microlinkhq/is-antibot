# Subscribe to `is-antibot` Release Dispatch Events

Every time `is-antibot` runs `pnpm run release`, it sends a `repository_dispatch` event with type:

`is-antibot-release-published`

This guide explains how any repository can subscribe to that event.

## 1. Add a Workflow in Your Repository

Create `.github/workflows/is-antibot-release.yml`:

```yml
name: is-antibot release subscriber

on:
  repository_dispatch:
    types:
      - is-antibot-release-published
  workflow_dispatch:

jobs:
  on-release:
    runs-on: ubuntu-latest
    steps:
      - name: Show payload
        run: |
          echo "Source repository: ${{ github.event.client_payload.sourceRepository }}"
          echo "Version: ${{ github.event.client_payload.version }}"
          echo "Tag: ${{ github.event.client_payload.tagName }}"
          echo "SHA: ${{ github.event.client_payload.sha }}"
          echo "Release URL: ${{ github.event.client_payload.url }}"
          echo "Providers URL: ${{ github.event.client_payload.providersUrl }}"
          echo "Schema URL: ${{ github.event.client_payload.schemaUrl }}"

      # Add your automation here:
      # - sync providers JSON
      # - run compatibility tests
      # - open a PR
```

## 2. Register Your Repository as a Dispatch Target

Since GitHub `repository_dispatch` is push-based, each receiver must be listed in the source workflow.

Current receivers are defined in [`main.yml`](../../.github/workflows/main.yml) under the "Dispatch release event" step. To add a new receiver, add another dispatch step targeting your `owner/repo`.

The source repo needs:

- Secret: `GH_TOKEN`
- With permission to dispatch events to the target repos.

## 3. Event Payload Contract

The dispatch payload includes:

- `sourceRepository`: source repo (`microlinkhq/is-antibot`)
- `version`: released version tag (for example `v1.7.0`)
- `tagName`: same as `version`
- `sha`: triggering commit SHA
- `url`: GitHub release URL
- `providersUrl`: raw URL to `src/providers.json` pinned at the release tag
- `schemaUrl`: raw URL to `src/schema.json` pinned at the release tag

## 4. Local Manual Test (Optional)

You can test the subscriber workflow by dispatching manually from a token that has access to your repo:

```bash
curl -L \
  -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/<owner>/<repo>/dispatches \
  -d '{"event_type":"is-antibot-release-published","client_payload":{"sourceRepository":"microlinkhq/is-antibot","version":"v0.0.0","tagName":"v0.0.0","sha":"test","url":"https://github.com/microlinkhq/is-antibot/releases","providersUrl":"https://raw.githubusercontent.com/microlinkhq/is-antibot/v0.0.0/src/providers.json","schemaUrl":"https://raw.githubusercontent.com/microlinkhq/is-antibot/v0.0.0/src/schema.json"}}'
```
