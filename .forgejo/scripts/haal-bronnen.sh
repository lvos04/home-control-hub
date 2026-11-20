#!/usr/bin/env bash
set -euo pipefail

# Het leessecret is alleen bij deze Git-opdrachten beschikbaar en komt niet in de remote-URL of gitconfig.
: "${BRON_LEESTOKEN:?BRON_LEESTOKEN ontbreekt}"
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=credential.helper
# shellcheck disable=SC2016  # Alleen de door Git gestarte helper mag de variabele uitbreiden.
export GIT_CONFIG_VALUE_0='!f() { printf "%s\n" "username=x-access-token" "password=$BRON_LEESTOKEN"; }; f'
server=https://git.medialeon.nl/leon

validator="$RUNNER_TEMP/appstore"
git init -q "$validator"
git -C "$validator" fetch -q --no-tags --depth=1 "$server/appstore-en-fork.git" "$VALIDATOR_COMMIT"
git -C "$validator" checkout -q --detach FETCH_HEAD

# De drifttests lezen de gepinde blobs met git show en de huidige bronbranch vanuit de werkmap.
hub="$RUNNER_TEMP/hubbron"
git init -q "$hub"
git -C "$hub" remote add origin "$server/ai-server-manager.git"
git -C "$hub" sparse-checkout set docs/platform-v2 design/ontwerptaal
for metadata in docs/platform-v2/CONTRACT_HERKOMST.json design/ontwerptaal/HERKOMST.json; do
  pin=$(jq -er .bron_commit "$metadata")
  tak=$(jq -er .bron_ref "$metadata")
  git -C "$hub" fetch -q --no-tags --depth=1 origin "$pin" "+refs/heads/$tak:refs/remotes/origin/$tak"
done
peilpin=$(jq -er .bron_commit design/ontwerptaal/HERKOMST.json)
git -C "$hub" show "$peilpin:design/ontwerptaal/bouw/sjabloon.py" > "$RUNNER_TEMP/sjabloon.py"
echo "HCH_PEIL_REFERENTIE=$RUNNER_TEMP/sjabloon.py" >> "$GITHUB_ENV"
echo "HCH_PEIL_REFERENTIE_VERPLICHT=1" >> "$GITHUB_ENV"
