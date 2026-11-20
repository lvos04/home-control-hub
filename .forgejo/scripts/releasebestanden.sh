#!/usr/bin/env bash
set -euo pipefail

: "${FORGEJO_TOKEN:?Jobtoken ontbreekt}"
releases="${GITHUB_API_URL%/}/repos/$GITHUB_REPOSITORY/releases"
api() {
  printf 'Authorization: token %s\n' "$FORGEJO_TOKEN" | curl --silent --show-error --header @- "$@"
}

info="$RUNNER_TEMP/hch-release.json"
status=$(api -o "$info" -w '%{http_code}' "$releases/tags/$GITHUB_REF_NAME")
case "$status" in
  200) ;;
  404)
    jq -n --arg tag "$GITHUB_REF_NAME" --rawfile body CHANGELOG.md \
      '{tag_name:$tag,name:("home-control-hub " + $tag),body:$body}' > "$RUNNER_TEMP/hch-changelog.json"
    api -f -H 'Content-Type: application/json' --data-binary "@$RUNNER_TEMP/hch-changelog.json" "$releases" > "$info"
    ;;
  *) echo "Opzoeken van de release gaf HTTP $status" >&2; exit 1 ;;
esac
assets="$releases/$(jq -er .id "$info")/assets"
for file in release/digests.json release/sbom.spdx.json; do
  name=${file##*/}
  # Eerst de nieuwe inhoud uploaden. Bij een onderbreking kan de volgende run de bijlage alsnog hernoemen.
  tijdelijk="$name.$(sha256sum "$file" | cut -d' ' -f1)"
  bijlagen=$(api -f "$assets")
  id_voor() { jq -r --arg naam "$1" '.[] | select(.name == $naam) | .id' <<< "$bijlagen"; }
  nieuw=$(id_voor "$tijdelijk")
  if [[ -z "$nieuw" ]]; then
    nieuw=$(api -f -F "attachment=@$file;type=application/json" "$assets?name=$tijdelijk" | jq -er .id)
  fi
  oud=$(id_voor "$name")
  if [[ -n "$oud" ]]; then
    api -f -X DELETE "$assets/$oud" > /dev/null
  fi
  api -f -X PATCH -H 'Content-Type: application/json' --data "$(jq -nc --arg name "$name" '{name:$name}')" \
    "$assets/$nieuw" | jq -er --arg name "$name" '.name | select(. == $name)'
done
