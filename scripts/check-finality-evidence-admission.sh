#!/usr/bin/env bash
# Pin the production wiring that keeps unverified finality evidence from owning
# a block-wide transport/cache slot. Behavioural limits live in
# test-pending-finality-cache; this check makes removal at either ingress route
# or at the authenticated-sender handoff fail as well.
set -euo pipefail

root="${1:-.}"
failed=0

require_marker() {
  local file="$1"
  local marker="$2"
  local description="$3"
  if ! grep -qF "$marker" "$root/$file"; then
    echo "FINALITY_ADMISSION_SOURCE_FAILURE: $description ($file)" >&2
    failed=1
  fi
}

require_marker validator/full-node-shard.cpp \
  'block_finality_broadcast_transport_id(finality)' \
  'public Plumtree finality route lost its evidence-aware transport id'
require_marker validator/full-node-fast-sync-overlays.cpp \
  'block_finality_broadcast_transport_id(finality)' \
  'fast-sync Plumtree finality route lost its evidence-aware transport id'
require_marker validator/full-node-shard.cpp \
  'src, BroadcastSource::public_overlay, false' \
  'public finality ingress no longer carries its authenticated sender'
require_marker validator/full-node-fast-sync-overlays.cpp \
  'src, BroadcastSource::fast_sync_overlay, true' \
  'fast-sync finality ingress no longer carries its authenticated sender'
require_marker validator/full-node-custom-overlays.cpp \
  'src, BroadcastSource::custom_overlay, !block_senders_.contains(local_id_)' \
  'custom-overlay finality ingress no longer carries its authenticated sender'
require_marker validator/full-node.cpp \
  'std::move(finality), source, td::optional<PublicKeyHash>(source_peer)' \
  'full-node finality ingress no longer hands the authenticated sender to the manager'
require_marker validator/manager.cpp \
  'PendingBlockFinalitySender::remote(*source_peer)' \
  'manager admission no longer partitions unverified evidence by authenticated sender'
require_marker validator/full-node-shard.cpp \
  'parsed_finality.received_bytes = received_bytes' \
  'public finality ingress no longer records the received payload size'
require_marker validator/full-node-fast-sync-overlays.cpp \
  'parsed_finality.received_bytes = received_bytes' \
  'fast-sync finality ingress no longer records the received payload size'
require_marker validator/full-node-custom-overlays.cpp \
  'parsed_finality.received_bytes = received_bytes' \
  'custom-overlay finality ingress no longer records the received payload size'
require_marker validator/manager.cpp \
  'auto accounted_bytes = finality.received_bytes' \
  'manager admission no longer charges the received payload bytes'

if grep -qF 'serialize_tl_object(finality.sig_set->tl(), true)' "$root/validator/manager.cpp"; then
  echo "FINALITY_ADMISSION_SOURCE_FAILURE: manager reserializes remote finality before admission" >&2
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "FINALITY_ADMISSION_SOURCE_OK: both Plumtree routes use evidence-aware ids and all ingress routes carry authenticated senders"
