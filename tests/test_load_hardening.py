from __future__ import annotations

import json
from pathlib import Path

import preflight.load as load_module
from preflight.load import _in_allow_order
from preflight.registry import PluginRegistry


def test_allow_order_never_parses_an_oversized_manifest(tmp_path: Path, monkeypatch):
    huge = tmp_path / "huge"
    small = tmp_path / "small"
    huge.mkdir()
    small.mkdir()
    (huge / "manifest.json").write_text(
        "x" * (PluginRegistry.MAX_MANIFEST_BYTES + 1), encoding="utf-8"
    )
    payload = {"package_id": "example.small"}
    (small / "manifest.json").write_text(json.dumps(payload), encoding="utf-8")

    original = json.loads
    sizes: list[int] = []

    def tracked(value, *args, **kwargs):
        sizes.append(len(value))
        return original(value, *args, **kwargs)

    monkeypatch.setattr(load_module.json, "loads", tracked)

    ordered = _in_allow_order(
        tmp_path,
        ["example.small"],
        max_manifest_bytes=PluginRegistry.MAX_MANIFEST_BYTES,
    )

    assert ordered[0].parent == small
    assert sizes == [len(json.dumps(payload))]
