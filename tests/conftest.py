# ------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2026 SEANERGYS Partners <https://seanergys.eu>
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
import typing

import pytest

import keyloom._envelope as _envelope


@pytest.fixture(autouse=True)
def cheap_argon2(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Lower the Argon2id cost, which otherwise dominates the test time.

    Tests marked ``real_kdf`` keep the real parameters of every algorithm.
    """
    if request.node.get_closest_marker("real_kdf") is not None:
        return
    real = _envelope._algorithms

    def cheap() -> dict[str, typing.Any]:
        return {
            name: {**parameters, "memory_cost": 8, "iterations": 1, "lanes": 1}
            for name, parameters in real().items()
        }

    monkeypatch.setattr(_envelope, "_algorithms", cheap)
