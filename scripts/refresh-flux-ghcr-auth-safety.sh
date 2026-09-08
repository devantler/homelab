#!/usr/bin/env bash

# Safety-critical helpers for refresh-flux-ghcr-auth.sh. Keep these functions
# side-effect free except where their names explicitly describe an operation so
# the production ordering and quorum gates can be exercised with command fakes.

readonly GHCR_PULL_VERIFIED_REVISION_ANNOTATION="platform.devantler.tech/ghcr-pull-verified-revision-v2"
readonly GHCR_PULL_VERIFIED_IMAGE_ANNOTATION="platform.devantler.tech/ghcr-pull-verified-image-v2"

# Name the nodes that still hold a drain fence, so a refusal is actionable
# without a live cluster query. A transaction killed before its EXIT trap
# released the fence leaves the annotation behind and every later deploy then
# refuses, which is correct but surfaces only as a bare
# `jq: error (at …): residual GHCR bridge ownership`.
#
# This reports; it never releases. Releasing needs the pre-claim schedulability
# the killed transaction did not record, so whether a node may be uncordoned is
# a decision this function cannot make and must not imply.
report_residual_bridge_ownership() {
  local nodes_file="$1"
  local held

  held="$(jq -r \
    --arg owner_annotation "platform.devantler.tech/ghcr-auth-drain-owner" \
    --arg recovery_annotation "platform.devantler.tech/ghcr-auth-drain-recovery" '
    .items[]
    | (.metadata.annotations[$owner_annotation] // "") as $owner
    | (.metadata.annotations[$recovery_annotation] // "") as $recovery
    | select($owner != "" or $recovery != "")
    | "  node \(.metadata.name) (cordoned=\(.spec.unschedulable == true))"
      + (if $owner == "" then ""
         else "\n    \($owner_annotation) = \($owner)" end)
      + (if $recovery == "" then ""
         else "\n    \($recovery_annotation) = \($recovery)" end)
  ' "${nodes_file}" 2>/dev/null)" || return 0
  [[ -n "${held}" ]] || return 0

  {
    printf 'Residual GHCR bridge ownership is held on:\n'
    printf '%s\n' "${held}"
    printf 'A previous transaction was killed before releasing its drain fence.\n'
    printf 'Node selection fails closed until the annotation(s) above are removed:\n'
    printf '  kubectl --context <ctx> annotate node <node> <annotation>-\n'
    printf 'A cordoned node is left cordoned on purpose: the killed transaction\n'
    printf 'recorded no pre-claim schedulability, so confirm the node should be\n'
    printf 'schedulable before uncordoning it.\n'
  } >&2
}

# Select nodes that have not completed the v2 proof for the incoming credential
# revision or exact image. A same-job proof may classify a marker-only loss as
# proof-only when it binds the same revision, image, node name, and immutable
# Node UID. This is the narrow handoff needed after `ksail cluster update`
# re-renders machine annotations; it never excuses a changed node or credential.
# Other credential-stale nodes require a reboot because containerd loads
# registry auth only at process start. Image-only drift still performs a fresh
# uncached pull proof.
select_talos_node_targets() {
  local nodes_file="$1"
  local desired_revision="$2"
  local operator_image="$3"
  local targets_file="$4"
  local reusable_proof_file="${5:-/dev/null}"
  local unsorted_targets="${targets_file}.unsorted"

  if ! jq -r \
    --arg revision "${desired_revision}" \
    --arg image "${operator_image}" \
    --arg revision_annotation "${GHCR_PULL_VERIFIED_REVISION_ANNOTATION}" \
    --arg image_annotation "${GHCR_PULL_VERIFIED_IMAGE_ANNOTATION}" \
    --arg owner_annotation "platform.devantler.tech/ghcr-auth-drain-owner" \
    --arg recovery_annotation "platform.devantler.tech/ghcr-auth-drain-recovery" \
    --slurpfile reusable_proof "${reusable_proof_file}" '
    ($reusable_proof[0].nodes // []) as $proved_nodes
    |
    if any(.items[];
      ((.metadata.annotations[$owner_annotation] // "") != "")
      or ((.metadata.annotations[$recovery_annotation] // "") != ""))
    then error("residual GHCR bridge ownership")
    else
      .items[]
      | (.metadata.annotations[$revision_annotation] // "") as $verified_revision
      | (.metadata.annotations[$image_annotation] // "") as $verified_image
      | .metadata.name as $node_name
      | (.metadata.uid // "") as $node_uid
      | ($proved_nodes | any(
          .name == $node_name and .uid == $node_uid
        )) as $can_restore_proof
      | select($verified_revision != $revision or $verified_image != $image)
      | (.metadata.labels // {}) as $labels
      | [
          (if (($labels | has("node-role.kubernetes.io/control-plane"))
            or ($labels | has("node-role.kubernetes.io/master")))
            then "1" else "0" end),
          .metadata.name,
          ([.status.addresses[]
            | select(.type == "InternalIP") | .address][0]),
          (if $can_restore_proof then "proof-only"
           elif $verified_revision != $revision then "reboot"
           else "image-only" end),
          $node_uid
        ]
      | @tsv
    end
  ' "${nodes_file}" >"${unsorted_targets}"; then
    report_residual_bridge_ownership "${nodes_file}"
    rm -f "${unsorted_targets}"
    return 1
  fi

  if ! LC_ALL=C sort -k1,1 -k2,2 \
    "${unsorted_targets}" >"${targets_file}"; then
    rm -f "${unsorted_targets}"
    return 1
  fi
  rm -f "${unsorted_targets}"
}

# Validate that an unclaimed node is still exactly what the capturing read saw,
# so a rejected atomic claim can be retried against a fresh resourceVersion.
# A Node object has several independent writers (kubelet status heartbeats, the
# cloud controller manager, the CNI operator), and any of their writes rejects
# the claim's resourceVersion test without changing anything relevant to drain
# safety. Retrying is only sound while every fact the caller captured still
# holds: same node identity, not being deleted, still unowned by this bridge,
# and unchanged scheduling intent. A concurrent cordon, ownership grab, taint
# edit, or node replacement therefore still refuses instead of retrying.
node_claim_preconditions_still_hold() {
  local state_file="$1"
  local initial_node_uid="$2"
  local was_cordoned="$3"
  local initial_node_taints="$4"

  jq -e \
    --arg owner_annotation \
    "platform.devantler.tech/ghcr-auth-drain-owner" \
    --arg recovery_annotation \
    "platform.devantler.tech/ghcr-auth-drain-recovery" \
    --arg uid "${initial_node_uid}" \
    --argjson was_cordoned "${was_cordoned}" \
    --argjson initial_taints "${initial_node_taints}" '
    def scheduling_taints:
      map(select((
        (.key == "node.kubernetes.io/unschedulable"
          and .effect == "NoSchedule"
          and (.value // "") == "")
        or (.key == "DeletionCandidateOfClusterAutoscaler"
          and .effect == "PreferNoSchedule")
      ) | not))
      | sort_by([.key, .effect, (.value // ""), (.timeAdded // "")]);
    .metadata.uid == $uid
    and .metadata.deletionTimestamp == null
    and ((.metadata.annotations[$owner_annotation] // "") == "")
    and ((.metadata.annotations[$recovery_annotation] // "") == "")
    and ((if (.spec.unschedulable // false) then 1 else 0 end)
      == $was_cordoned)
    and (((.spec.taints // []) | scheduling_taints)
      == ($initial_taints | scheduling_taints))
  ' "${state_file}" >/dev/null
}

# Validate the scheduling state captured immediately before a Talos reboot.
# The bridge must still own its serialization annotation while the node stays
# cordoned; neither a bridge-created nor a pre-existing cordon may proceed after
# UID, taint, deletion, ownership, or schedulability drift. The unschedulable
# taint mirrors spec.unschedulable and is excluded from the comparison; all
# other scheduling intent is preserved.
node_scheduling_state_is_safe_to_reboot() {
  local state_file="$1"
  local was_cordoned="$2"
  local owner_token="$3"
  local initial_node_uid="$4"
  local initial_node_taints="$5"

  jq -e \
    --arg owner_annotation \
    "platform.devantler.tech/ghcr-auth-drain-owner" \
    --arg owner "${owner_token}" \
    --arg uid "${initial_node_uid}" \
    --argjson was_cordoned "${was_cordoned}" \
    --argjson initial_taints "${initial_node_taints}" '
    def scheduling_taints:
      map(select((
        (.key == "node.kubernetes.io/unschedulable"
          and .effect == "NoSchedule"
          and (.value // "") == "")
        or (.key == "DeletionCandidateOfClusterAutoscaler"
          and .effect == "PreferNoSchedule")
      ) | not))
      | sort_by([.key, .effect, (.value // ""), (.timeAdded // "")]);
    .metadata.uid == $uid
    and .metadata.deletionTimestamp == null
    and .spec.unschedulable == true
    and .metadata.annotations[$owner_annotation] == $owner
    and (((.spec.taints // []) | scheduling_taints)
      == ($initial_taints | scheduling_taints))
  ' "${state_file}" >/dev/null
}

# Kubernetes may briefly retain its Ready-condition lifecycle taints after the
# Ready condition itself turns True. Cilium likewise owns its agent-not-ready
# startup taint and can clear it just after kubelet reports Ready. While waiting
# for those controller-owned taints to disappear, preserve every other part of
# the captured scheduling intent exactly; a replacement, ownership change,
# uncordon, or unrelated taint must still fail closed immediately.
node_scheduling_state_is_safe_while_lifecycle_taints_clear() {
  local state_file="$1"
  local was_cordoned="$2"
  local owner_token="$3"
  local initial_node_uid="$4"
  local initial_node_taints="$5"

  jq -e \
    --arg owner_annotation \
    "platform.devantler.tech/ghcr-auth-drain-owner" \
    --arg owner "${owner_token}" \
    --arg uid "${initial_node_uid}" \
    --argjson was_cordoned "${was_cordoned}" \
    --argjson initial_taints "${initial_node_taints}" '
    def scheduling_taints:
      map(select((
        (.key == "node.kubernetes.io/unschedulable"
          and .effect == "NoSchedule"
          and (.value // "") == "")
        or (.key == "DeletionCandidateOfClusterAutoscaler"
          and .effect == "PreferNoSchedule")
        or .key == "node.kubernetes.io/not-ready"
        or .key == "node.kubernetes.io/unreachable"
        or .key == "node.cilium.io/agent-not-ready"
      ) | not))
      | sort_by([.key, .effect, (.value // ""), (.timeAdded // "")]);
    .metadata.uid == $uid
    and .metadata.deletionTimestamp == null
    and .spec.unschedulable == true
    and .metadata.annotations[$owner_annotation] == $owner
    and (((.spec.taints // []) | scheduling_taints)
      == ($initial_taints | scheduling_taints))
  ' "${state_file}" >/dev/null
}

node_has_lifecycle_taints() {
  local state_file="$1"

  jq -e '
    any(.spec.taints[]?;
      .key == "node.kubernetes.io/not-ready"
      or .key == "node.kubernetes.io/unreachable"
      or .key == "node.cilium.io/agent-not-ready")
  ' "${state_file}" >/dev/null
}

# Bind a selected node name to the same UID, InternalIP, and role immediately
# before any Talos API mutation. Names and addresses can be reused when an
# autoscaler replaces a node between inventory reads; the immutable UID keeps
# the bridge from patching or rebooting the wrong machine.
selected_node_identity_is_current() {
  local state_file="$1"
  local expected_name="$2"
  local expected_uid="$3"
  local expected_ip="$4"
  local expected_role="$5"

  jq -e \
    --arg name "${expected_name}" \
    --arg uid "${expected_uid}" \
    --arg ip "${expected_ip}" \
    --arg role "${expected_role}" '
    .metadata.name == $name
    and .metadata.uid == $uid
    and .metadata.deletionTimestamp == null
    and ([.status.addresses[]?
      | select(.type == "InternalIP") | .address] == [$ip])
    and ((((.metadata.labels // {})
      | has("node-role.kubernetes.io/control-plane"))
      or (((.metadata.labels // {})
        | has("node-role.kubernetes.io/master")))) == ($role == "1"))
  ' "${state_file}" >/dev/null
}

# Reapply and verify the complete live Kubernetes pull-consumer fanout. Flux and
# External Secrets reconcile independently, so a long Talos roll can overlap an
# hourly controller pass that restores the previous Git value.
sync_and_verify_kubernetes_fanout() {
  local namespace
  local rc

  patch_variables_base || {
    rc=$?
    return "${rc}"
  }
  force_sync_resource pushsecret flux-system seed-ghcr || {
    rc=$?
    return "${rc}"
  }
  for namespace in "$@"; do
    force_sync_resource externalsecret "${namespace}" ghcr-auth || {
      rc=$?
      return "${rc}"
    }
    verify_consumer_secret "${namespace}" || {
      rc=$?
      return "${rc}"
    }
  done
}

# Existing clusters must make every Kubernetes pull consumer safe before the
# first Talos reboot drains application pods, then establish the same proof
# again after the roll. The root Flux Secret remains last so a failed node roll
# or a live-controller race cannot advance reconciliation onto a partial state.
stage_fanout_before_talos() {
  local desired_revision="$1"
  local operator_image="$2"
  local talos_sync_result="$3"
  local stage_attempt=0
  local stage_attempts="${TALOS_CONVERGENCE_ATTEMPTS:-3}"
  local rc
  shift 3

  while ((stage_attempt < stage_attempts)); do
    stage_attempt=$((stage_attempt + 1))
    sync_and_verify_kubernetes_fanout "$@" || {
      rc=$?
      return "${rc}"
    }
    sync_talos_registry_auth \
      "${desired_revision}" \
      "${operator_image}" \
      "${talos_sync_result}" || {
      rc=$?
      return "${rc}"
    }
    if grep -Fxq -- clean "${talos_sync_result}"; then
      record_runtime_proof "${desired_revision}" "${operator_image}" || {
        rc=$?
        return "${rc}"
      }
      patch_root_secret || {
        rc=$?
        return "${rc}"
      }
      return 0
    fi
    # `deselected` means every target was proved removed before it was touched,
    # so nothing was verified and this pass cannot authorise root cutover. It is
    # a reason to converge again, exactly like `processed` -- not an invalid
    # result, and not a deploy failure. Only `clean` above cuts root auth over.
    if ! grep -Fxq -- processed "${talos_sync_result}" &&
      ! grep -Fxq -- deselected "${talos_sync_result}"; then
      echo "::error::Talos synchronization returned an invalid convergence result; root Flux auth remains unchanged."
      return 1
    fi
    # A node mutation can overlap another controller reconciliation. Re-prove
    # every consumer, then require a whole node convergence pass with no
    # mutations before root cutover. This closes both race domains together.
  done

  echo "::error::Kubernetes pull-consumer and Talos node state did not converge after ${stage_attempts} transaction rounds; root Flux auth remains unchanged."
  return 1
}

# Prove every OTHER production control-plane member is Kubernetes-Ready,
# reachable through the Talos etcd status RPC, and alarm-free immediately before
# taking one member down. Any inventory, command, or output-shape ambiguity is a
# hard failure: blocking a reboot is safer than guessing about quorum.
other_control_planes_safe_to_reboot() {
  local rebooting="$1"
  local kube_context="$2"
  local state_dir="$3"
  local live_nodes_file="${state_dir}/control-plane-health-${rebooting}.json"
  local peer_file="${state_dir}/control-plane-etcd-peers-${rebooting}.tsv"
  local peer_name
  local peer_ip
  local peer_number=0
  local status_file
  local alarms_file

  if ! kubectl \
    --context "${kube_context}" \
    get nodes \
    --output json \
    >"${live_nodes_file}" 2>/dev/null; then
    echo "Could not re-read control-plane health before rebooting ${rebooting}."
    return 1
  fi

  if ! jq -er --arg rebooting "${rebooting}" '
    [
      .items[]
      | select(.metadata.name != $rebooting)
      | (.metadata.labels // {}) as $labels
      | select(($labels | has("node-role.kubernetes.io/control-plane"))
        or ($labels | has("node-role.kubernetes.io/master")))
      | {
          name: .metadata.name,
          internal_ips: [
            .status.addresses[]?
            | select(.type == "InternalIP")
            | .address
          ],
          ready: any(.status.conditions[]?;
            .type == "Ready" and .status == "True")
        }
    ] as $peers
    | if ($peers | length) < 2 then
        error("fewer than two other control-plane peers")
      elif all($peers[];
        .ready == true
        and (.name | type == "string" and test("^[^\\t\\r\\n]+$"))
        and (.internal_ips | length) == 1
        and (.internal_ips[0]
          | type == "string"
          and test("^[^\\t\\r\\n]+$"))) | not then
        error("a control-plane peer is unready or has an invalid InternalIP")
      elif ([$peers[].internal_ips[0]] | unique | length)
        != ($peers | length) then
        error("control-plane peer InternalIPs are not unique")
      else
        $peers[] | [.name, .internal_ips[0]] | @tsv
      end
  ' "${live_nodes_file}" >"${peer_file}" 2>/dev/null; then
    echo "Could not prove that every other control plane is Ready with a unique InternalIP before rebooting ${rebooting}."
    return 1
  fi

  while IFS=$'\t' read -r peer_name peer_ip; do
    peer_number=$((peer_number + 1))
    status_file="${state_dir}/etcd-status-${rebooting}-${peer_number}.txt"
    alarms_file="${state_dir}/etcd-alarms-${rebooting}-${peer_number}.txt"

    if ! talosctl \
      --nodes "${peer_ip}" \
      etcd status \
      >"${status_file}" 2>&1; then
      echo "Could not read etcd status from control-plane peer ${peer_name}."
      return 1
    fi
    if ! awk -v expected_node="${peer_ip}" '
      NR == 1 {
        common = ($1 == "NODE")
        common = common && ($2 == "MEMBER")
        common = common && ($3 == "DB") && ($4 == "SIZE")
        common = common && ($5 == "IN") && ($6 == "USE")
        common = common && ($7 == "LEADER")
        common = common && ($8 == "RAFT") && ($9 == "INDEX")
        common = common && ($10 == "RAFT") && ($11 == "TERM")
        common = common && ($12 == "RAFT") && ($13 == "APPLIED")
        common = common && ($14 == "INDEX") && ($15 == "LEARNER")
        compact = (NF == 16) && ($16 == "ERRORS")
        extended = (NF == 18)
        extended = extended && ($16 == "PROTOCOL")
        extended = extended && ($17 == "STORAGE") && ($18 == "ERRORS")
        header = common && (compact || extended)
        expected_data_fields = compact ? 12 : 14
        next
      }
      NF == 0 { next }
      {
        data_rows++
        if ($1 == expected_node) {
          rows++
          # Talos emits either the compact 12-field row or a 14-field row with
          # protocol/storage versions. LEARNER is field 12 in both, and any
          # status error adds fields after the expected healthy row.
          if (NF != expected_data_fields || $12 != "false") {
            unsafe = 1
          }
        }
      }
      END {
        exit !(header && data_rows == 1 && rows == 1 && !unsafe)
      }
    ' "${status_file}"; then
      echo "Control-plane peer ${peer_name} is an etcd learner, reports a status error, or returned an unrecognized status response."
      return 1
    fi

    if ! talosctl \
      --nodes "${peer_ip}" \
      etcd alarm list \
      >"${alarms_file}" 2>&1; then
      echo "Could not read etcd alarms from control-plane peer ${peer_name}."
      return 1
    fi
    if ! awk '
      NF == 0 { next }
      {
        nonempty++
        if (nonempty == 1) {
          header = ($1 == "NODE" && $2 == "MEMBER" && $3 == "ALARM")
          next
        }
        rows++
      }
      END {
        # Talos 1.13 emits no bytes for a successful empty alarm list, while
        # older clients emit a header-only table. Both shapes prove no alarms.
        exit !((nonempty == 0) || (header && rows == 0))
      }
    ' "${alarms_file}"; then
      echo "Control-plane peer ${peer_name} has an etcd alarm or returned an unrecognized alarm response."
      return 1
    fi
  done <"${peer_file}"
}

# Select drain fences that are provably orphaned, for reclaim by the caller.
#
# The caller supplies this only after acquiring the synchronization Lease, and
# acquisition refuses any non-empty holderIdentity — so at that instant no
# bridge transaction was running, and a fence is only ever held by a running
# transaction. Every fence present at that moment is therefore ownerless, which
# is the liveness proof that makes reclaim safe without a run id or a timestamp.
#
# A fence carrying a recovery journal is deliberately EXCLUDED: the journal
# records an interrupted bootstrap whose phase decides what is safe, bootstrap
# recovery owns it, and clearing it would destroy the only durable record of an
# in-flight Talos mutation.
select_orphaned_node_fences() {
  local nodes_file="$1"
  local targets_file="$2"

  jq -r \
    --arg owner_annotation "platform.devantler.tech/ghcr-auth-drain-owner" \
    --arg recovery_annotation "platform.devantler.tech/ghcr-auth-drain-recovery" \
    --arg phase_annotation "platform.devantler.tech/ghcr-auth-drain-phase" '
    .items[]
    | (.metadata.annotations // {}) as $annotations
    | select((($annotations[$owner_annotation]) // "") != "")
    | select((($annotations[$recovery_annotation]) // "") == "")
    # Only a fence that never reached Talos mutation is provably safe to clear.
    # A missing phase is a PRE-#3070 fence of unknown depth, so it fails closed
    # here exactly like "mutating" does -- absence is never read as innocence.
    | select((($annotations[$phase_annotation]) // "") == "claimed")
    | [
        .metadata.name,
        (.metadata.uid // ""),
        $annotations[$owner_annotation],
        ((.spec.unschedulable // false) | tostring)
      ]
    | @tsv
  ' "${nodes_file}" >"${targets_file}"
}
