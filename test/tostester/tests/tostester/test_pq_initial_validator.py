from __future__ import annotations

import pytest
from tostester.pq_initial_validator import make_deterministic_pq_initial_validator


class FakeNode:
    def __init__(self) -> None:
        self.calls: list[tuple[bytes, bytes]] = []

    def make_initial_pq_validator(self, validator_id: bytes, seed: bytes) -> None:
        self.calls.append((validator_id, seed))


def test_deterministic_pq_initial_validator_is_stable_and_indexed() -> None:
    first = FakeNode()
    repeated = FakeNode()
    second = FakeNode()

    make_deterministic_pq_initial_validator(first, 0)
    make_deterministic_pq_initial_validator(repeated, 0)
    make_deterministic_pq_initial_validator(second, 1)

    assert first.calls == repeated.calls
    assert first.calls != second.calls
    assert all(len(value) == 32 for value in first.calls[0])


@pytest.mark.parametrize("index", [-1, 2**32, True])
def test_deterministic_pq_initial_validator_rejects_invalid_index(index: int) -> None:
    with pytest.raises(ValueError, match="outside uint32"):
        make_deterministic_pq_initial_validator(FakeNode(), index)
