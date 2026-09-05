#!/usr/bin/env bash
# Pin the shape of .github/workflows/regenerate-publish-workflow-approved-revisions.yaml
# (#3552, third child of #3308).
#
# WHY THIS EXISTS. The workflow's job is to turn a moved approved-revision set into ONE
# draft pull request and to turn anything it cannot resolve into a RED run. Both halves
# are properties of the workflow's SHAPE, not of any script it calls, and every one of
# them regresses silently: an interpolated branch name opens a second pull request per
# run instead of updating the first; `continue-on-error` on the generator, or an
# `if: always()` on the pull-request step, turns an unresolved consumer into a pull
# request that dropped it; a widened App-token grant or a lost `persist-credentials:
# false` hands the job more than it needs; a missing `environment: prod` resolves
# KUBE_CONFIG to the empty string so the generator refuses every consumer on the cluster
# half — a red run that looks like a broken cluster. None of those fails CI by itself.
#
# Every assertion is ABLATED: a copy of the workflow is mutated in exactly one place and
# the check must fail naming that assertion. A check that cannot fail is not a check.
#
# yq (mikefarah v4) reads the YAML; no network, no secrets. Bash 3.2 compatible.
# The yq mutations below carry literal `${{ … }}` GitHub expressions on purpose — the
# ablations are ABOUT interpolation reaching the workflow — so they must not expand here.
# shellcheck disable=SC2016
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root_dir
readonly workflow="${root_dir}/.github/workflows/regenerate-publish-workflow-approved-revisions.yaml"
readonly generator='scripts/generate-publish-workflow-approved-revisions.sh'
readonly guard='scripts/guard-publish-workflow-approved-revisions.sh'
readonly data_file='scripts/publish-workflow-approved-revisions.tsv'
readonly generated_paths='scripts/publish-workflow-approved-revisions.tsv
k8s/bases/apps/github-config/oci-repository.yaml
k8s/bases/apps/ascoachingogvaner/oci-repository.yaml
k8s/providers/hetzner/apps/aws/oci-repository.yaml
k8s/bases/apps/wedding-app/oci-repository.yaml'
readonly endpoint_script='scripts/use-prod-stable-api-endpoint.sh'

work_dir="$(mktemp -d)"
readonly work_dir
cleanup() { rm -rf "${work_dir}"; }
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v yq >/dev/null 2>&1 || fail 'yq is required'
[ -f "${workflow}" ] || fail "workflow not found: ${workflow}"

# q <file> <expr> → the expression's value, or the empty string when it is absent.
# Deliberately NOT `expr // ""`: yq's alternative operator treats a real `false` as
# absent, so `cancel-in-progress: false` would read as missing and A3 could never pass.
q() {
  yq -r "$2" "$1" | sed 's/^null$//'
}

# ── The check ─────────────────────────────────────────────────────────────────────────────
# check <file>: prints "ok" and exits 0, or prints "VIOLATION <id>: <why>" and exits 1.
# The id is what the ablations key on, so a mutation that trips a DIFFERENT assertion
# than the one it targets is caught as a wrongly-attributed proof.
check() {
  local f="$1"

  # A1 — runs on a daily cadence AND on demand.
  local cron
  cron="$(q "$f" '.on.schedule[0].cron')"
  case "${cron}" in
    *' '*' '*' '*' '*) ;;
    *) printf 'VIOLATION A1: no five-field schedule cron (got "%s")\n' "${cron}"; return 1 ;;
  esac
  [ "$(yq -r '.on | has("workflow_dispatch")' "$f")" = 'true' ] ||
    { printf 'VIOLATION A1: no workflow_dispatch trigger\n'; return 1; }

  # A2 — no ambient grant: the App token carries every write.
  if ! { [ "$(yq -r '.permissions | tag' "$f")" = '!!map' ] &&
    [ "$(yq -r '.permissions | length' "$f")" = '0' ]; }; then
    printf 'VIOLATION A2: top-level permissions is not the empty map\n'
    return 1
  fi
  if ! { [ "$(q "$f" '.jobs.regenerate.permissions.contents')" = 'read' ] &&
    [ "$(yq -r '.jobs.regenerate.permissions | length' "$f")" = '1' ]; }; then
    printf 'VIOLATION A2: the job grants more than contents: read to GITHUB_TOKEN\n'
    return 1
  fi

  # A3 — one run at a time, never cut off mid pull request.
  [ "$(q "$f" '.concurrency.queue')" = 'single' ] ||
    { printf 'VIOLATION A3: concurrency.queue is not single\n'; return 1; }
  [ "$(q "$f" '.concurrency.cancel-in-progress')" = 'false' ] ||
    { printf 'VIOLATION A3: concurrency.cancel-in-progress is not false\n'; return 1; }

  # A4 — the cluster half needs the prod environment's KUBE_CONFIG.
  [ "$(q "$f" '.jobs.regenerate.environment')" = 'prod' ] ||
    { printf 'VIOLATION A4: the job does not run in environment prod\n'; return 1; }

  # Step indices, by what each step DOES rather than by name. The two App-token steps
  # are told apart by their id, because their `uses:` is identical.
  local steps gen_idx guard_idx pr_idx read_token_idx write_token_idx checkout_idx
  steps="$(yq -r '.jobs.regenerate.steps | length' "$f")"
  gen_idx="$(yq -r ".jobs.regenerate.steps | to_entries | map(select(.value.run // \"\" | contains(\"${generator}\"))) | .[0].key // \"\"" "$f")"
  guard_idx="$(yq -r ".jobs.regenerate.steps | to_entries | map(select(.value.run // \"\" | contains(\"${guard}\"))) | .[0].key // \"\"" "$f")"
  pr_idx="$(yq -r '.jobs.regenerate.steps | to_entries | map(select(.value.uses // "" | contains("peter-evans/create-pull-request@"))) | .[0].key // ""' "$f")"
  read_token_idx="$(yq -r '.jobs.regenerate.steps | to_entries | map(select((.value.uses // "" | contains("actions/create-github-app-token@")) and .value.id == "consumer-token")) | .[0].key // ""' "$f")"
  write_token_idx="$(yq -r '.jobs.regenerate.steps | to_entries | map(select((.value.uses // "" | contains("actions/create-github-app-token@")) and .value.id == "app-token")) | .[0].key // ""' "$f")"
  checkout_idx="$(yq -r '.jobs.regenerate.steps | to_entries | map(select(.value.uses // "" | contains("actions/checkout@"))) | .[0].key // ""' "$f")"

  # A5 — the generator runs, against prod, on the READ-ONLY consumer token. Reading the
  # consumers with the write token would hand a compromised generator push and
  # pull-request rights over every consumer, which is what the split exists to prevent.
  [ -n "${gen_idx}" ] || { printf 'VIOLATION A5: no step runs %s\n' "${generator}"; return 1; }
  [ "$(q "$f" ".jobs.regenerate.steps[${gen_idx}].env.PUBLISH_KUBE_CONTEXT")" = 'admin@prod' ] ||
    { printf 'VIOLATION A5: the generator step does not pin PUBLISH_KUBE_CONTEXT to admin@prod\n'; return 1; }
  case "$(q "$f" ".jobs.regenerate.steps[${gen_idx}].env.GH_TOKEN")" in
    *'steps.consumer-token.outputs.token'*) ;;
    *) printf 'VIOLATION A5: the generator step does not read GH_TOKEN from the consumer-read token\n'; return 1 ;;
  esac

  # A6 — TWO tokens, each minted for exactly its half. One installation token carries
  # one permission set across every repository it names, so a single token covering
  # this repository and the consumers would grant write over all of them.
  [ -n "${read_token_idx}" ] || { printf 'VIOLATION A6: no consumer-read App-token step (id: consumer-token)\n'; return 1; }
  [ -n "${write_token_idx}" ] || { printf 'VIOLATION A6: no platform-write App-token step (id: app-token)\n'; return 1; }
  local read_grants write_grants
  read_grants="$(yq -r ".jobs.regenerate.steps[${read_token_idx}].with | to_entries | map(select(.key | test(\"^permission-\"))) | map(.key + \"=\" + .value) | sort | join(\",\")" "$f")"
  [ "${read_grants}" = 'permission-actions=read,permission-contents=read' ] ||
    { printf 'VIOLATION A6: consumer-read token grants are "%s", not exactly actions=read,contents=read\n' "${read_grants}"; return 1; }
  write_grants="$(yq -r ".jobs.regenerate.steps[${write_token_idx}].with | to_entries | map(select(.key | test(\"^permission-\"))) | map(.key + \"=\" + .value) | sort | join(\",\")" "$f")"
  [ "${write_grants}" = 'permission-contents=write,permission-pull-requests=write' ] ||
    { printf 'VIOLATION A6: platform-write token grants are "%s", not exactly contents=write,pull-requests=write\n' "${write_grants}"; return 1; }

  # A7 — the checkout keeps no credential in the tree, and is pinned to the default
  # branch so a dispatch from another ref cannot carry that ref's commits into the
  # fixed regeneration branch.
  [ -n "${checkout_idx}" ] || { printf 'VIOLATION A7: no checkout step\n'; return 1; }
  [ "$(q "$f" ".jobs.regenerate.steps[${checkout_idx}].with.persist-credentials")" = 'false' ] ||
    { printf 'VIOLATION A7: checkout does not set persist-credentials: false\n'; return 1; }
  local coref
  coref="$(q "$f" ".jobs.regenerate.steps[${checkout_idx}].with.ref")"
  [ -n "${coref}" ] ||
    { printf 'VIOLATION A7: the checkout pins no ref, so a dispatch from another ref builds the regeneration branch on it\n'; return 1; }
  case "${coref}" in
    *'${{'*) printf 'VIOLATION A7: the checkout ref is interpolated ("%s")\n' "${coref}"; return 1 ;;
  esac

  # A8 — one open pull request: a fixed branch, a draft, signed, exactly the set and matchers.
  [ -n "${pr_idx}" ] || { printf 'VIOLATION A8: no create-pull-request step\n'; return 1; }
  local branch
  branch="$(q "$f" ".jobs.regenerate.steps[${pr_idx}].with.branch")"
  [ -n "${branch}" ] || { printf 'VIOLATION A8: the pull-request step names no branch\n'; return 1; }
  case "${branch}" in
    *'${{'*) printf 'VIOLATION A8: the pull-request branch is interpolated ("%s"), so each run would open a new pull request\n' "${branch}"; return 1 ;;
  esac
  [ "$(q "$f" ".jobs.regenerate.steps[${pr_idx}].with.draft")" = 'true' ] ||
    { printf 'VIOLATION A8: the pull request is not opened as a draft\n'; return 1; }
  [ "$(q "$f" ".jobs.regenerate.steps[${pr_idx}].with.sign-commits")" = 'true' ] ||
    { printf 'VIOLATION A8: the pull-request commit is not API-signed\n'; return 1; }
  [ "$(q "$f" ".jobs.regenerate.steps[${pr_idx}].with.add-paths")" = "${generated_paths}" ] ||
    { printf 'VIOLATION A8: add-paths must contain exactly the set and four consumer manifests\n'; return 1; }
  case "$(q "$f" ".jobs.regenerate.steps[${pr_idx}].with.token")" in
    *'steps.app-token.outputs.token'*) ;;
    *) printf 'VIOLATION A8: the pull request is not opened with the App token\n'; return 1 ;;
  esac

  # A9 — a failed resolution is a red run, never a pull request that dropped a consumer:
  # nothing swallows a failure, and the guard re-reads the moved set before the push.
  local i
  i=0
  while [ "${i}" -lt "${steps}" ]; do
    [ "$(q "$f" ".jobs.regenerate.steps[${i}].continue-on-error")" = '' ] ||
      { printf 'VIOLATION A9: step %s carries continue-on-error\n' "${i}"; return 1; }
    i=$((i + 1))
  done
  case "$(q "$f" ".jobs.regenerate.steps[${pr_idx}].if")" in
    *'always()'* | *'failure()'* | *'!cancelled()'*)
      printf 'VIOLATION A9: the pull-request step runs after a failure\n'; return 1 ;;
  esac
  [ -n "${guard_idx}" ] || { printf 'VIOLATION A9: no step runs %s on the moved set\n' "${guard}"; return 1; }
  if ! { [ "${gen_idx}" -lt "${guard_idx}" ] && [ "${guard_idx}" -lt "${pr_idx}" ]; }; then
    printf 'VIOLATION A9: steps are not ordered generator (%s) < guard (%s) < pull request (%s)\n' "${gen_idx}" "${guard_idx}" "${pr_idx}"
    return 1
  fi


  # A10 — each token reaches exactly its own half.
  # create-github-app-token given neither `owner` nor `repositories` mints a token
  # scoped to the repository the job runs in, so every consumer read would 404 and
  # the generator would refuse on the pin half — a permanently red daily run. The
  # expected consumer set is read from the data file, so adding a consumer there
  # without adding it here fails this check rather than failing in production.
  # The write token must NOT name a consumer: one token carries one permission set,
  # so a consumer listed there would inherit contents/pull-requests write.
  local read_scoped write_scoped consumers consumer missing leaked
  [ -n "$(q "$f" ".jobs.regenerate.steps[${read_token_idx}].with.owner")" ] ||
    { printf 'VIOLATION A10: the consumer-read token names no owner, so it cannot be scoped past this repository\n'; return 1; }
  [ -n "$(q "$f" ".jobs.regenerate.steps[${write_token_idx}].with.owner")" ] ||
    { printf 'VIOLATION A10: the platform-write token names no owner\n'; return 1; }
  read_scoped=" $(q "$f" ".jobs.regenerate.steps[${read_token_idx}].with.repositories" | tr '\n' ' ') "
  write_scoped=" $(q "$f" ".jobs.regenerate.steps[${write_token_idx}].with.repositories" | tr '\n' ' ') "
  case "${write_scoped}" in
    *' platform '*) ;;
    *) printf 'VIOLATION A10: the write token omits platform, so it cannot push the branch or open the pull request\n'; return 1 ;;
  esac
  # Read the consumers one per LINE, and keep the loop in THIS shell. `for c in
  # $(…)` splits on whitespace rather than lines, and a pipeline would put the
  # loop in a subshell where the accumulated result is lost. A `case` inside a
  # command substitution is not an option either: the pattern's own `)` closes
  # the substitution early — measured, it captured the loop's source as data.
  consumers="$(awk 'NR > 1 { print $1 }' "${root_dir}/${data_file}" | sort -u)"
  missing=''
  leaked=''
  while IFS= read -r consumer; do
    [ -n "${consumer}" ] || continue
    case "${read_scoped}" in
      *" ${consumer} "*) ;;
      *) missing="${missing}${consumer} " ;;
    esac
    case "${write_scoped}" in
      *" ${consumer} "*) leaked="${leaked}${consumer} " ;;
    esac
  done <<< "${consumers}"
  [ -z "${missing}" ] ||
    { printf 'VIOLATION A10: consumer(s) %sare in the approved set but not in the consumer-read token repositories list\n' "${missing}"; return 1; }
  [ -z "${leaked}" ] ||
    { printf 'VIOLATION A10: consumer(s) %sare in the WRITE token repositories list, which grants them contents/pull-requests write\n' "${leaked}"; return 1; }

  # A11 — ONE pull request even across refs. The pushed branch is fixed, so a
  # dispatch from another ref and the scheduled run on the default branch contend
  # for the same pull request; a ref-keyed concurrency group puts them in different
  # groups and lets them race. An unpinned base makes such a dispatch open its pull
  # request against the dispatched ref instead of the default branch.
  case "$(q "$f" '.concurrency.group')" in
    *'github.head_ref'* | *'github.ref'*)
      printf 'VIOLATION A11: the concurrency group varies with the dispatch ref while the pushed branch is fixed\n'; return 1 ;;
  esac
  local base
  base="$(q "$f" ".jobs.regenerate.steps[${pr_idx}].with.base")"
  [ -n "${base}" ] ||
    { printf 'VIOLATION A11: the pull-request step pins no base, so a dispatch from another ref targets that ref\n'; return 1; }
  case "${base}" in
    *'${{'*) printf 'VIOLATION A11: the pull-request base is interpolated ("%s")\n' "${base}"; return 1 ;;
  esac

  # A12 — the generated pull request discloses that an agent authored it. This
  # action supplies the COMPLETE body, so without the prefix every pull request it
  # opens violates the repository convention that AGENTS.md states.
  case "$(q "$f" ".jobs.regenerate.steps[${pr_idx}].with.body")" in
    '> 🤖 Generated by the'*) ;;
    *) printf 'VIOLATION A12: the generated pull-request body does not begin with the agent disclosure line\n'; return 1 ;;
  esac

  # A13 — the prod API endpoint is resolved AFTER the kubeconfig and BEFORE any
  # Kubernetes API call. KUBE_CONFIG can outlive the control-plane node whose public
  # IP it names, and `cluster update` rolls those nodes, so the generator would read
  # OCIRepositories through a dead address against a healthy cluster.
  local endpoint_idx kube_idx
  endpoint_idx="$(yq -r ".jobs.regenerate.steps | to_entries | map(select(.value.run // \"\" | contains(\"${endpoint_script}\"))) | .[0].key // \"\"" "$f")"
  kube_idx="$(yq -r '.jobs.regenerate.steps | to_entries | map(select(.value.env.KUBE_CONFIG // "" | length > 0)) | .[0].key // ""' "$f")"
  [ -n "${endpoint_idx}" ] || { printf 'VIOLATION A13: no step runs %s\n' "${endpoint_script}"; return 1; }
  [ -n "${kube_idx}" ] || { printf 'VIOLATION A13: no step restores KUBE_CONFIG\n'; return 1; }
  if ! { [ "${kube_idx}" -lt "${endpoint_idx}" ] && [ "${endpoint_idx}" -lt "${gen_idx}" ]; }; then
    printf 'VIOLATION A13: steps are not ordered kubeconfig (%s) < endpoint (%s) < generator (%s)\n' "${kube_idx}" "${endpoint_idx}" "${gen_idx}"
    return 1
  fi
  case "$(q "$f" ".jobs.regenerate.steps[${endpoint_idx}].env.HCLOUD_TOKEN")" in
    *'secrets.HCLOUD_TOKEN'*) ;;
    *) printf 'VIOLATION A13: the endpoint step does not receive HCLOUD_TOKEN\n'; return 1 ;;
  esac
  # A14 — the pull-request step is NOT gated on `moved`. When a consumer's rollout is
  # reverted the observed set returns to the committed one, `moved` goes false, and a
  # gated step skips — leaving the pull request an earlier run opened standing with
  # the superseded set, still mergeable, after this workflow has established it is no
  # longer current. Running the action on the unchanged path is the precondition for
  # reconciling that; A9 separately pins that a FAILURE still stops it.
  case "$(q "$f" ".jobs.regenerate.steps[${pr_idx}].if")" in
    '') ;;
    *) printf 'VIOLATION A14: the pull-request step is conditional ("%s"), so a set that returns to baseline leaves a stale pull request open\n' "$(q "$f" ".jobs.regenerate.steps[${pr_idx}].if")"; return 1 ;;
  esac

  # A15 — update the matchers before change detection and enforced validation.
  local writer_idx moved_idx
  writer_idx="$(yq -r '.jobs.regenerate.steps | to_entries | map(select(.value.run // "" | contains("write-publish-workflow-matchers.sh"))) | .[0].key // ""' "$f")"
  moved_idx="$(yq -r '.jobs.regenerate.steps | to_entries | map(select(.value.id == "moved")) | .[0].key // ""' "$f")"
  if ! { [ -n "${writer_idx}" ] && [ -n "${moved_idx}" ] &&
    [ "${gen_idx}" -lt "${writer_idx}" ] && [ "${writer_idx}" -lt "${moved_idx}" ] &&
    [ "${moved_idx}" -lt "${guard_idx}" ]; }; then
    printf 'VIOLATION A15: require generator < writer < change detection < guard\n'; return 1
  fi
  [ "$(q "$f" ".jobs.regenerate.steps[${writer_idx}].if")" = '' ] ||
    { printf 'VIOLATION A15: the matcher writer must run unconditionally after generation\n'; return 1; }
  [ "$(q "$f" ".jobs.regenerate.steps[${guard_idx}].env.APPROVED_REVISIONS_ENFORCE")" = '1' ] ||
    { printf 'VIOLATION A15: the regeneration guard must enforce exact approved revisions\n'; return 1; }

  printf 'ok\n'
}

# ── Control: the committed workflow passes ────────────────────────────────────────────────
# Bind the workflow's explicit path fence to the consumer manifests the writer discovers.
# A relocated consumer must update the automation boundary in the same change.
discovered_paths="$(bash -c 'source "$1"; printf "%s" "$observed" | cut -f2' _ \
  "${root_dir}/scripts/publish-workflow-approved-revisions.lib.sh")"
actual_paths="$(printf '%s\n%s\n' "${data_file}" "${discovered_paths}" | sort)"
[ "$(printf '%s\n' "${generated_paths}" | sort)" = "$actual_paths" ] ||
  fail 'the regeneration path fence does not match the discovered consumer manifests'

out="$(check "${workflow}")" || fail "the committed workflow violates its own contract: ${out}"
[ "${out}" = 'ok' ] || fail "unexpected check output on the committed workflow: ${out}"

# ── Ablations: each mutation must trip EXACTLY the assertion it targets ───────────────────
# ablate <id> <description> <yq mutation>
ablate() {
  local id="$1" description="$2" mutation="$3" copy out
  copy="${work_dir}/${id}-$$.yaml"
  cp "${workflow}" "${copy}"
  yq -i "${mutation}" "${copy}"
  # The mutation must have changed the file, or the ablation proved nothing.
  if cmp -s "${workflow}" "${copy}"; then
    fail "ablation ${id} (${description}) did not change the workflow — vacuous"
  fi
  if out="$(check "${copy}")"; then
    fail "ablation ${id} (${description}) was NOT caught (check printed: ${out})"
  fi
  case "${out}" in
    "VIOLATION ${id}:"*) ;;
    *) fail "ablation ${id} (${description}) tripped the wrong assertion: ${out}" ;;
  esac
}

ablate A1 'schedule removed'                 'del(.on.schedule)'
ablate A1 'workflow_dispatch removed'        'del(.on.workflow_dispatch)'
ablate A2 'ambient contents: write'          '.permissions.contents = "write"'
ablate A2 'job granted pull-requests: write' '.jobs.regenerate.permissions.pull-requests = "write"'
ablate A3 'cancel-in-progress true'          '.concurrency.cancel-in-progress = true'
ablate A3 'queue max'                        '.concurrency.queue = "max"'
ablate A4 'environment removed'              'del(.jobs.regenerate.environment)'
ablate A5 'kube context unpinned'            '(.jobs.regenerate.steps[] | select(.run // "" | contains("generate-publish-workflow-approved-revisions.sh")) | .env.PUBLISH_KUBE_CONTEXT) = "admin@local"'
ablate A5 'generator on GITHUB_TOKEN'        '(.jobs.regenerate.steps[] | select(.run // "" | contains("generate-publish-workflow-approved-revisions.sh")) | .env.GH_TOKEN) = "${{ github.token }}"'
ablate A6 'token widened to workflows'       '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-github-app-token")) | .with.permission-workflows) = "write"'
ablate A6 'token actions grant dropped'      '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-github-app-token")) | .with) |= del(.permission-actions)'
ablate A7 'credentials persisted'            '(.jobs.regenerate.steps[] | select(.uses // "" | contains("actions/checkout")) | .with.persist-credentials) = true'
ablate A8 'branch interpolated'              '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-pull-request")) | .with.branch) = "regenerate-${{ github.run_id }}"'
ablate A8 'not a draft'                      '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-pull-request")) | .with.draft) = false'
ablate A8 'unsigned commit'                  '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-pull-request")) | .with) |= del(.sign-commits)'
ablate A8 'add-paths widened'                '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-pull-request")) | .with.add-paths) = "."'
ablate A9 'generator continue-on-error'      '(.jobs.regenerate.steps[] | select(.run // "" | contains("generate-publish-workflow-approved-revisions.sh")) | .continue-on-error) = true'
ablate A9 'pull request on always()'         '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-pull-request")) | .if) = "always()"'
ablate A9 'guard step removed'               'del(.jobs.regenerate.steps[] | select(.run // "" | contains("guard-publish-workflow-approved-revisions.sh")))'
ablate A9 'guard moved after the pull request' '.jobs.regenerate.steps = ([.jobs.regenerate.steps[] | select((.run // "" | contains("guard-publish-workflow-approved-revisions.sh")) | not)] + [.jobs.regenerate.steps[] | select(.run // "" | contains("guard-publish-workflow-approved-revisions.sh"))])'
ablate A10 'token repositories removed'      '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-github-app-token")) | .with) |= del(.repositories)'
ablate A10 'token owner removed'             '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-github-app-token")) | .with) |= del(.owner)'
ablate A10 'one consumer dropped from scope' '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-github-app-token")) | .with.repositories) = "platform\n.github\naws\nwedding-app\n"'
ablate A11 'concurrency keyed on the ref'    '.concurrency.group = "${{ github.workflow }}-${{ github.ref }}"'
ablate A11 'pull-request base removed'       '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-pull-request")) | .with) |= del(.base)'
ablate A11 'pull-request base interpolated'  '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-pull-request")) | .with.base) = "${{ github.ref_name }}"'
ablate A12 'disclosure dropped from the body' '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-pull-request")) | .with.body) = "The per-consumer approved-revision set moved.\n"'
ablate A13 'endpoint step removed'           'del(.jobs.regenerate.steps[] | select(.run // "" | contains("use-prod-stable-api-endpoint.sh")))'
ablate A13 'endpoint moved after the generator' '.jobs.regenerate.steps = ([.jobs.regenerate.steps[] | select((.run // "" | contains("use-prod-stable-api-endpoint.sh")) | not)] + [.jobs.regenerate.steps[] | select(.run // "" | contains("use-prod-stable-api-endpoint.sh"))])'
ablate A13 'endpoint step loses HCLOUD_TOKEN' '(.jobs.regenerate.steps[] | select(.run // "" | contains("use-prod-stable-api-endpoint.sh")) | .env) |= del(.HCLOUD_TOKEN)'

ablate A5 'generator on the WRITE token'     '(.jobs.regenerate.steps[] | select(.run // "" | contains("generate-publish-workflow-approved-revisions.sh")) | .env.GH_TOKEN) = "${{ steps.app-token.outputs.token }}"'
ablate A6 'read token given contents write'  '(.jobs.regenerate.steps[] | select(.id == "consumer-token") | .with.permission-contents) = "write"'
ablate A6 'write token given actions read'   '(.jobs.regenerate.steps[] | select(.id == "app-token") | .with.permission-actions) = "read"'
ablate A6 'consumer-read token step removed' 'del(.jobs.regenerate.steps[] | select(.id == "consumer-token"))'
ablate A7 'checkout ref removed'             '(.jobs.regenerate.steps[] | select(.uses // "" | contains("actions/checkout")) | .with) |= del(.ref)'
ablate A7 'checkout ref interpolated'        '(.jobs.regenerate.steps[] | select(.uses // "" | contains("actions/checkout")) | .with.ref) = "${{ github.ref_name }}"'
ablate A10 'a consumer added to the WRITE token' '(.jobs.regenerate.steps[] | select(.id == "app-token") | .with.repositories) = "platform\nwedding-app\n"'
ablate A10 'a consumer dropped from the READ token' '(.jobs.regenerate.steps[] | select(.id == "consumer-token") | .with.repositories) = ".github\naws\nwedding-app\n"'
ablate A14 'pull-request step re-gated on moved' '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-pull-request")) | .if) = "steps.moved.outputs.moved == '"'"'true'"'"'"'

ablate A15 'writer removed' 'del(.jobs.regenerate.steps[] | select(.run // "" | contains("write-publish-workflow-matchers.sh")))'
ablate A15 'writer moved after guard' '.jobs.regenerate.steps = ([.jobs.regenerate.steps[] | select((.run // "" | contains("write-publish-workflow-matchers.sh")) | not)] + [.jobs.regenerate.steps[] | select(.run // "" | contains("write-publish-workflow-matchers.sh"))])'
ablate A15 'writer gated off' '(.jobs.regenerate.steps[] | select(.run // "" | contains("write-publish-workflow-matchers.sh")) | .if) = "false"'
ablate A15 'guard enforcement off' '(.jobs.regenerate.steps[] | select(.run // "" | contains("guard-publish-workflow-approved-revisions.sh")) | .env.APPROVED_REVISIONS_ENFORCE) = "0"'
ablate A8 'consumer matcher omitted' '(.jobs.regenerate.steps[] | select(.uses // "" | contains("create-pull-request")) | .with.add-paths) = "scripts/publish-workflow-approved-revisions.tsv"'
ablate A9 'writer failure ignored' '(.jobs.regenerate.steps[] | select(.run // "" | contains("write-publish-workflow-matchers.sh")) | .continue-on-error) = true'

# Execute the actual change-detection step in a disposable checkout. This proves
# that the PR boundary handles each matcher, staged changes, and unrelated paths.
detection="${work_dir}/detect.sh"
yq -r '.jobs.regenerate.steps[] | select(.id == "moved") | .run' "${workflow}" > "${detection}"
checkout="${work_dir}/checkout"
mkdir -p "${checkout}"
(
  cd "${checkout}"
  git init -q
  while IFS= read -r path; do
    mkdir -p "$(dirname "$path")"
    printf 'original\n' > "$path"
    git add -- "$path"
  done <<< "${generated_paths}"
  git -c user.name=Test -c user.email=test@example.invalid -c commit.gpgsign=false commit -qm fixture
  export GITHUB_OUTPUT="${work_dir}/outputs"
  bash "${detection}" > "${work_dir}/detection.log"
  grep -qx 'moved=false' "$GITHUB_OUTPUT" || fail 'unchanged checkout must report false'
  while IFS= read -r path; do
    : > "$GITHUB_OUTPUT"
    printf 'updated\n' >> "$path"
    bash "${detection}" > "${work_dir}/detection.log"
    grep -qx 'moved=true' "$GITHUB_OUTPUT" || fail "allowed update was not detected: $path"
    git add -- "$path"
    : > "$GITHUB_OUTPUT"
    bash "${detection}" > "${work_dir}/detection.log"
    grep -qx 'moved=true' "$GITHUB_OUTPUT" || fail "staged update was not detected: $path"
    git restore --staged --worktree -- "$path"
  done <<< "${generated_paths}"
  mkdir -p k8s/bases/apps/other
  printf 'unrelated\n' > k8s/bases/apps/other/oci-repository.yaml
  if bash "${detection}" > "${work_dir}/detection.log" 2>&1; then
    fail 'unrelated untracked manifest was allowed'
  fi
  grep -Fq 'outside the approved set and matchers' "${work_dir}/detection.log" || fail 'unrelated-file refusal was not the expected cause'
  git add -- k8s/bases/apps/other/oci-repository.yaml
  if bash "${detection}" > "${work_dir}/detection.log" 2>&1; then
    fail 'unrelated staged manifest was allowed'
  fi
)

printf 'test-regenerate-publish-workflow-approved-revisions: 1 control + 45 ablations + change-detection cases passed\n'
