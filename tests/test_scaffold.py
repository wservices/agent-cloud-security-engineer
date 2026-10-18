"""Offline scaffold smoke test for the cloud-security-engineer role.

Validates the distribution manifest and every bundled SKILL.md without any
network or cloud access. Uses only the stdlib + PyYAML + pytest.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "skills"

REQUIRED_MANIFEST_FIELDS = (
    "name",
    "version",
    "description",
    "hermes_requires",
    "author",
    "license",
    "distribution_owned",
    "env_requires",
)

# The SKILL.md body headings, in the exact required order.
REQUIRED_SECTIONS = (
    "When to Use",
    "Prerequisites",
    "How to Run",
    "Quick Reference",
    "Procedure",
    "Pitfalls",
    "Verification",
)

VALID_PLATFORMS = {"linux", "macos", "windows"}
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _load_manifest() -> dict:
    data = yaml.safe_load((ROOT / "distribution.yaml").read_text(encoding="utf-8"))
    assert isinstance(data, dict), "distribution.yaml must parse to a mapping"
    return data


def _skill_files() -> list[Path]:
    files = sorted(SKILLS_DIR.glob("*/SKILL.md"))
    assert files, "no skills/*/SKILL.md found"
    return files


def _split_frontmatter(text: str) -> tuple[dict, str]:
    assert text.startswith("---\n"), "SKILL.md must start with YAML frontmatter"
    end = text.index("\n---", 4)
    fm = yaml.safe_load(text[4:end])
    body = text[end + 4:]
    assert isinstance(fm, dict), "frontmatter must parse to a mapping"
    return fm, body


def test_manifest_parses_and_has_required_fields():
    manifest = _load_manifest()
    for field in REQUIRED_MANIFEST_FIELDS:
        assert field in manifest, f"distribution.yaml missing '{field}'"
    assert manifest["name"] == "cloud-security-engineer"
    assert SEMVER_RE.match(str(manifest["version"])), "version must be semver"
    assert isinstance(manifest["env_requires"], list) and manifest["env_requires"]
    for entry in manifest["env_requires"]:
        assert "name" in entry and "description" in entry
        assert "required" in entry, f"{entry.get('name')} must declare 'required'"


@pytest.mark.parametrize("skill_file", _skill_files(), ids=lambda p: p.parent.name)
def test_skill_frontmatter_valid(skill_file: Path):
    fm, _ = _split_frontmatter(skill_file.read_text(encoding="utf-8"))

    # name matches the directory
    assert fm.get("name") == skill_file.parent.name

    # description: <= 60 chars and ends with a period
    desc = fm.get("description", "")
    assert isinstance(desc, str) and desc, "description required"
    assert len(desc) <= 60, f"description >60 chars ({len(desc)}): {desc!r}"
    assert desc.endswith("."), f"description must end with '.': {desc!r}"

    # version: semver
    assert SEMVER_RE.match(str(fm.get("version", ""))), "version must be semver"

    # platforms subset of the allowed set
    platforms = fm.get("platforms")
    assert isinstance(platforms, list) and platforms, "platforms must be a non-empty list"
    assert set(platforms) <= VALID_PLATFORMS, f"invalid platforms: {platforms}"


@pytest.mark.parametrize("skill_file", _skill_files(), ids=lambda p: p.parent.name)
def test_skill_sections_present_and_ordered(skill_file: Path):
    _, body = _split_frontmatter(skill_file.read_text(encoding="utf-8"))
    headings = re.findall(r"^##\s+(.+?)\s*$", body, re.MULTILINE)
    # keep only the required ones, preserving document order
    seen = [h for h in headings if h in REQUIRED_SECTIONS]
    assert seen == list(REQUIRED_SECTIONS), (
        f"{skill_file.parent.name}: sections {seen} != required order "
        f"{list(REQUIRED_SECTIONS)}"
    )
