#!/usr/bin/env bash
# Upload .github/dockerhub-description.md to the Docker Hub repository page.
#
# Docker Hub does not read the description from the image, so it has to be sent
# separately. The registry login `docker login` performs does not grant access to
# the Hub web API, which is why this needs a personal access token of its own
# rather than reusing the stored credential.
set -euo pipefail

REPOSITORY="${1:-shortplanet/network-atlas}"
DESCRIPTION_FILE="${2:-.github/dockerhub-description.md}"
NAMESPACE="${REPOSITORY%%/*}"
NAME="${REPOSITORY##*/}"

if [[ -z "${DOCKERHUB_TOKEN:-}" ]]; then
  cat >&2 <<'USAGE'
DOCKERHUB_TOKEN is not set.

Create a token at https://app.docker.com/settings/personal-access-tokens with
"Read & Write" permission, then:

    export DOCKERHUB_TOKEN='dckr_pat_...'
    make docker-describe

The token is read from the environment and never written to a file.
USAGE
  exit 2
fi

if [[ ! -f "$DESCRIPTION_FILE" ]]; then
  echo "No such file: $DESCRIPTION_FILE" >&2
  exit 2
fi

USERNAME="${DOCKERHUB_USER:-$NAMESPACE}"

jwt="$(
  curl -fsS -X POST https://hub.docker.com/v2/auth/token \
    -H 'Content-Type: application/json' \
    --data-binary @<(
      printf '{"identifier":"%s","secret":"%s"}' "$USERNAME" "$DOCKERHUB_TOKEN"
    ) | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))'
)"

if [[ -z "$jwt" ]]; then
  echo "Docker Hub did not return a token. Check DOCKERHUB_USER and DOCKERHUB_TOKEN." >&2
  exit 1
fi

# Build the JSON body with a real JSON encoder: a Markdown file contains quotes,
# backslashes and newlines that would break a hand-assembled string.
body="$(python3 -c '
import json, sys
print(json.dumps({"full_description": open(sys.argv[1], encoding="utf-8").read()}))
' "$DESCRIPTION_FILE")"

status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -X PATCH "https://hub.docker.com/v2/repositories/${NAMESPACE}/${NAME}/" \
    -H "Authorization: Bearer ${jwt}" \
    -H 'Content-Type: application/json' \
    --data-binary "$body"
)"

if [[ "$status" == "200" ]]; then
  echo "Updated the description for ${REPOSITORY} from ${DESCRIPTION_FILE}."
  echo "See https://hub.docker.com/r/${NAMESPACE}/${NAME}"
else
  echo "Docker Hub returned HTTP ${status}." >&2
  echo "403 usually means the token lacks Read & Write on this repository." >&2
  exit 1
fi
