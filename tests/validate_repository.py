"""Repository quality checks for the Sigma Rule Library."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote
from uuid import UUID

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RULES_DIRECTORY = REPOSITORY_ROOT / "rules"
RULE_DOCUMENTATION_DIRECTORY = REPOSITORY_ROOT / "docs" / "rules"

EXPECTED_RULE_COUNT = 15

REQUIRED_RULE_FIELDS = {
    "title",
    "id",
    "status",
    "description",
    "references",
    "author",
    "date",
    "license",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
}

ALLOWED_STATUSES = {
    "stable",
    "test",
    "experimental",
    "deprecated",
    "unsupported",
}

ALLOWED_LEVELS = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}

MITRE_TECHNIQUE_PATTERN = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$")
MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
EXTERNAL_LINK_PATTERN = re.compile(r"^(?:https?://|mailto:)", re.IGNORECASE)

MOJIBAKE_PATTERNS = (
    "\ufffd",
    "\u7ab6",
    "\u7b0f",
    "\u7aca",
)


class ValidationReport:
    """Collect validation results and print a readable summary."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.checks: list[str] = []

    def pass_check(self, message: str) -> None:
        self.checks.append(message)
        print(f"[PASS] {message}")

    def fail(self, message: str) -> None:
        self.errors.append(message)
        print(f"[FAIL] {message}")

    def finish(self) -> int:
        print()
        print("=== Repository Validation Summary ===")
        print(f"Checks passed: {len(self.checks)}")
        print(f"Errors found: {len(self.errors)}")

        if self.errors:
            print()
            print("The repository did not pass validation.")
            return 1

        print("All repository quality checks passed.")
        return 0


def load_sigma_rule(rule_path: Path, report: ValidationReport) -> dict | None:
    """Load one Sigma YAML file and report parsing problems."""

    try:
        with rule_path.open("r", encoding="utf-8") as rule_file:
            content = yaml.safe_load(rule_file)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        report.fail(f"{rule_path.relative_to(REPOSITORY_ROOT)}: {error}")
        return None

    if not isinstance(content, dict):
        report.fail(
            f"{rule_path.relative_to(REPOSITORY_ROOT)} does not contain "
            "a YAML mapping."
        )
        return None

    return content


def validate_rule_count(rule_paths: list[Path], report: ValidationReport) -> None:
    """Confirm that the repository contains the planned number of rules."""

    if len(rule_paths) != EXPECTED_RULE_COUNT:
        report.fail(
            f"Expected {EXPECTED_RULE_COUNT} Sigma rules, "
            f"but found {len(rule_paths)}."
        )
        return

    report.pass_check(f"Found exactly {EXPECTED_RULE_COUNT} Sigma rules")


def validate_rule_metadata(
    rule_paths: list[Path],
    report: ValidationReport,
) -> None:
    """Validate required metadata, UUIDs, tags, and documentation."""

    observed_ids: dict[str, Path] = {}
    observed_titles: dict[str, Path] = {}

    for rule_path in rule_paths:
        relative_rule_path = rule_path.relative_to(REPOSITORY_ROOT)
        rule = load_sigma_rule(rule_path, report)

        if rule is None:
            continue

        missing_fields = sorted(REQUIRED_RULE_FIELDS.difference(rule))

        if missing_fields:
            report.fail(
                f"{relative_rule_path}: missing required fields: "
                f"{', '.join(missing_fields)}"
            )
            continue

        title = rule.get("title")
        rule_id = str(rule.get("id"))
        status = rule.get("status")
        level = rule.get("level")
        references = rule.get("references")
        tags = rule.get("tags")
        detection = rule.get("detection")

        if not isinstance(title, str) or not title.strip():
            report.fail(f"{relative_rule_path}: title is empty or invalid")
        elif title in observed_titles:
            report.fail(
                f"{relative_rule_path}: duplicate title also used by "
                f"{observed_titles[title].relative_to(REPOSITORY_ROOT)}"
            )
        else:
            observed_titles[title] = rule_path

        try:
            UUID(rule_id)
        except ValueError:
            report.fail(f"{relative_rule_path}: invalid UUID: {rule_id}")
        else:
            if rule_id in observed_ids:
                report.fail(
                    f"{relative_rule_path}: duplicate UUID also used by "
                    f"{observed_ids[rule_id].relative_to(REPOSITORY_ROOT)}"
                )
            else:
                observed_ids[rule_id] = rule_path

        if status not in ALLOWED_STATUSES:
            report.fail(
                f"{relative_rule_path}: unsupported status value: {status}"
            )

        if level not in ALLOWED_LEVELS:
            report.fail(
                f"{relative_rule_path}: unsupported level value: {level}"
            )

        if not isinstance(references, list) or not references:
            report.fail(
                f"{relative_rule_path}: references must be a non-empty list"
            )

        if not isinstance(tags, list) or not tags:
            report.fail(f"{relative_rule_path}: tags must be a non-empty list")
        elif not any(
            isinstance(tag, str) and MITRE_TECHNIQUE_PATTERN.match(tag)
            for tag in tags
        ):
            report.fail(
                f"{relative_rule_path}: no MITRE ATT&CK technique tag found"
            )

        if not isinstance(detection, dict):
            report.fail(
                f"{relative_rule_path}: detection must be a YAML mapping"
            )
        elif "condition" not in detection:
            report.fail(
                f"{relative_rule_path}: detection condition is missing"
            )

        relative_from_rules = rule_path.relative_to(RULES_DIRECTORY)
        expected_documentation = (
            RULE_DOCUMENTATION_DIRECTORY / relative_from_rules
        ).with_suffix(".md")

        if not expected_documentation.is_file():
            report.fail(
                f"{relative_rule_path}: documentation is missing at "
                f"{expected_documentation.relative_to(REPOSITORY_ROOT)}"
            )

    if len(observed_ids) == len(rule_paths):
        report.pass_check("All rule UUIDs are valid and unique")

    if len(observed_titles) == len(rule_paths):
        report.pass_check("All rule titles are present and unique")

    if not any(
        "missing required fields" in error
        or "unsupported status" in error
        or "unsupported level" in error
        or "references must" in error
        or "tags must" in error
        or "no MITRE" in error
        or "detection must" in error
        or "detection condition" in error
        for error in report.errors
    ):
        report.pass_check(
            "All rules contain valid metadata, detection logic, and ATT&CK tags"
        )

    if not any("documentation is missing" in error for error in report.errors):
        report.pass_check("Every Sigma rule has corresponding documentation")


def collect_markdown_files() -> list[Path]:
    """Return the project Markdown files that require link checking."""

    markdown_files = [
        REPOSITORY_ROOT / "README.md",
        REPOSITORY_ROOT / "PROJECT_PROGRESS.md",
    ]

    markdown_files.extend(
        sorted((REPOSITORY_ROOT / "docs").rglob("*.md"))
    )

    return [path for path in markdown_files if path.is_file()]


def validate_markdown_links(
    markdown_files: list[Path],
    report: ValidationReport,
) -> None:
    """Confirm that relative Markdown links resolve locally."""

    broken_links: list[str] = []

    for markdown_path in markdown_files:
        text = markdown_path.read_text(encoding="utf-8")

        for match in MARKDOWN_LINK_PATTERN.finditer(text):
            raw_target = match.group(1).strip()

            if not raw_target or EXTERNAL_LINK_PATTERN.match(raw_target):
                continue

            target_without_anchor = raw_target.split("#", maxsplit=1)[0]

            if not target_without_anchor:
                continue

            target_without_title = target_without_anchor.split(
                " ",
                maxsplit=1,
            )[0].strip("<>")

            decoded_target = unquote(target_without_title)
            resolved_target = (
                markdown_path.parent / decoded_target
            ).resolve()

            if not resolved_target.exists():
                broken_links.append(
                    f"{markdown_path.relative_to(REPOSITORY_ROOT)} "
                    f"-> {raw_target}"
                )

    if broken_links:
        for broken_link in broken_links:
            report.fail(f"Broken Markdown link: {broken_link}")
        return

    report.pass_check("All internal Markdown links resolve correctly")


def validate_readme_inventory(
    rule_paths: list[Path],
    report: ValidationReport,
) -> None:
    """Confirm that every rule is linked from the project README."""

    readme_path = REPOSITORY_ROOT / "README.md"
    readme_text = readme_path.read_text(encoding="utf-8")
    missing_links: list[str] = []

    for rule_path in rule_paths:
        relative_rule_path = rule_path.relative_to(
            REPOSITORY_ROOT
        ).as_posix()

        if relative_rule_path not in readme_text:
            missing_links.append(relative_rule_path)

    if missing_links:
        for missing_link in missing_links:
            report.fail(f"README rule inventory is missing: {missing_link}")
        return

    report.pass_check("README contains links to all 15 Sigma rules")


def validate_text_quality(
    rule_paths: list[Path],
    markdown_files: list[Path],
    report: ValidationReport,
) -> None:
    """Check relevant files for formatting and encoding problems."""

    files_to_check = [
        *rule_paths,
        *markdown_files,
        REPOSITORY_ROOT / "tests" / "validate_repository.py",
    ]

    formatting_errors: list[str] = []

    for file_path in files_to_check:
        try:
            text = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            report.fail(
                f"Unable to read "
                f"{file_path.relative_to(REPOSITORY_ROOT)}: {error}"
            )
            continue

        relative_path = file_path.relative_to(REPOSITORY_ROOT)

        for line_number, line in enumerate(text.splitlines(), start=1):
            if line != line.rstrip():
                formatting_errors.append(
                    f"{relative_path}:{line_number}: trailing whitespace"
                )

            if file_path.suffix in {".yml", ".yaml"} and "\t" in line:
                formatting_errors.append(
                    f"{relative_path}:{line_number}: tab found in YAML"
                )

        for pattern in MOJIBAKE_PATTERNS:
            if pattern in text:
                formatting_errors.append(
                    f"{relative_path}: possible encoding damage: {pattern}"
                )

    if formatting_errors:
        for formatting_error in formatting_errors:
            report.fail(formatting_error)
        return

    report.pass_check(
        "No trailing whitespace, YAML tabs, or damaged characters found"
    )


def main() -> int:
    """Execute all repository quality checks."""

    report = ValidationReport()

    rule_paths = sorted(RULES_DIRECTORY.rglob("*.yml"))
    markdown_files = collect_markdown_files()

    print("Sigma Rule Library - Repository Validation")
    print("=" * 42)
    print()

    validate_rule_count(rule_paths, report)
    validate_rule_metadata(rule_paths, report)
    validate_markdown_links(markdown_files, report)
    validate_readme_inventory(rule_paths, report)
    validate_text_quality(rule_paths, markdown_files, report)

    return report.finish()


if __name__ == "__main__":
    sys.exit(main())