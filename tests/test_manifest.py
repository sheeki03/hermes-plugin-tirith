from __future__ import annotations

import re

import yaml

import tirith as plugin
from tirith._settings import CHOICES, DEFAULTS

from conftest import PLUGIN_DIR, ROOT, RecordingCtx

MANIFEST = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8"))
TYPES = {"str": str, "int": int, "bool": bool, "list": list}


def test_manifest_basics():
    assert MANIFEST["name"] == "tirith"
    assert MANIFEST["version"] == plugin.__version__ == "0.1.0"
    assert MANIFEST["requires_hermes"] == ">=0.21.5"
    assert MANIFEST["license"] == "MIT"
    assert MANIFEST["author"] == "tirith contributors"
    assert "provides_tools" not in MANIFEST


def test_config_schema_defaults_match_the_code():
    schema = MANIFEST["config_schema"]
    assert set(schema) == set(DEFAULTS)
    for key, spec in schema.items():
        assert spec["default"] == DEFAULTS[key], key
        assert isinstance(spec["default"], TYPES[spec["type"]]), key
        assert spec.get("description"), key
        if key in CHOICES:
            assert tuple(spec["choices"]) == CHOICES[key] or set(spec["choices"]) == set(CHOICES[key]), key


def test_declared_hooks_match_registration():
    ctx = RecordingCtx()
    plugin.register(ctx)
    assert sorted(MANIFEST["provides_hooks"]) == sorted(ctx.hooks)


def test_readme_documents_every_setting():
    readme = (PLUGIN_DIR / "README.md").read_text(encoding="utf-8")
    for key in DEFAULTS:
        assert re.search(rf"^\| `{key}` \|", readme, re.M), key


def test_changelog_lists_this_version():
    changelog = (PLUGIN_DIR / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"^## {re.escape(plugin.__version__)}\b", changelog, re.M)


def test_licence_is_shipped_with_the_plugin():
    root = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert root == (PLUGIN_DIR / "LICENSE").read_text(encoding="utf-8")
    assert root.startswith("MIT License")
    assert "Copyright (c) 2026 tirith contributors" in root


def test_installed_tree_has_only_runtime_files():
    allowed = {
        "__init__.py",
        "_decide.py",
        "_locate.py",
        "_scan.py",
        "_settings.py",
        "_state.py",
        "_version.py",
        "plugin.yaml",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
    }
    shipped = {
        p.relative_to(PLUGIN_DIR).as_posix()
        for p in PLUGIN_DIR.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    assert shipped == allowed


def test_runtime_code_is_stdlib_only():
    allowed_roots = {
        "__future__",
        "dataclasses",
        "functools",
        "hashlib",
        "importlib",
        "json",
        "logging",
        "math",
        "os",
        "re",
        "shutil",
        "signal",
        "subprocess",
        "sys",
        "tempfile",
        "threading",
        "time",
        "typing",
        "unicodedata",
        "collections",
    }
    for source in PLUGIN_DIR.glob("*.py"):
        for line in source.read_text(encoding="utf-8").splitlines():
            match = re.match(r"\s*(?:from|import)\s+([A-Za-z_][\w.]*)", line)
            if match and not match.group(1).startswith("."):
                assert match.group(1).split(".")[0] in allowed_roots, (source.name, line)
