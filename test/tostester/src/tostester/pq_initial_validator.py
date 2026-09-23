"""Deterministic post-quantum initial validators for repository test networks."""

from __future__ import annotations

import hashlib
from typing import Protocol


class InitialPqValidatorNode(Protocol):
    def make_initial_pq_validator(self, validator_id: bytes, seed: bytes) -> None: ...


_DOMAIN = b"tos-test-pq-initial-validator-v1\x00"


def make_deterministic_pq_initial_validator(node: InitialPqValidatorNode, index: int) -> None:
    """Provision one stable, test-only ML-DSA validator identity by committee index."""
    if isinstance(index, bool) or not 0 <= index < 2**32:
        raise ValueError(f"post-quantum initial validator index is outside uint32: {index!r}")
    encoded_index = index.to_bytes(4, "big")
    validator_id = hashlib.sha256(_DOMAIN + b"validator-id\x00" + encoded_index).digest()
    seed = hashlib.sha256(_DOMAIN + b"consensus-seed\x00" + encoded_index).digest()
    node.make_initial_pq_validator(validator_id, seed)
