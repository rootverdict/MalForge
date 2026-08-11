"""Generate MalForge's searchable code reference from the live repository.

The output is intentionally generated documentation. Do not hand-edit it.
Run this script from any working directory after source changes:

    python tools/generate_code_reference.py
"""

from __future__ import annotations

import ast
import hashlib
import html
import re
from datetime import date
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "MALFORGE_CODE_REFERENCE.md"
SKIP_DIRS = {
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    ".codex-handbook-deps",
    ".codex-test-deps",
    "build",
    "dist",
    "output",
    "validation",
    "node_modules",
    "site-packages",
    "venv",
}


def _is_virtualenv_dir(name: str) -> bool:
    """Match any local virtualenv directory, such as `.venv` or `.venv312`."""
    return name.startswith(".venv") or name == "venv"
SKIP_FILES = {
    "MALFORGE_CODE_REFERENCE.md",
    "MALFORGE_COMPLETE_PROJECT_HANDBOOK.md",
    "MALFORGE_HANDBOOK.md",
}
SOURCE_SUFFIXES = {
    ".py",
    ".md",
    ".yml",
    ".yaml",
    ".toml",
    ".txt",
    ".json",
    ".csv",
    ".xml",
    ".example",
}
SOURCE_NAMES = {".gitignore", "LICENSE", "Makefile"}


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _is_skipped(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if path.name in SKIP_FILES:
        return True
    return any(part in SKIP_DIRS or _is_virtualenv_dir(part) for part in relative.parts)


def _repository_files() -> list[Path]:
    return sorted(
        (
            path
            for path in ROOT.rglob("*")
            if path.is_file() and not _is_skipped(path)
        ),
        key=_relative,
    )


def _source_files(files: Iterable[Path]) -> list[Path]:
    return [
        path
        for path in files
        if path.suffix.lower() in SOURCE_SUFFIXES or path.name in SOURCE_NAMES
    ]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def _attack_version() -> str:
    constants = _read_text(ROOT / "core" / "constants.py")
    match = re.search(r'^ATTACK_VERSION\s*=\s*"([^"]+)"', constants, flags=re.MULTILINE)
    return match.group(1) if match else "unknown"


def _digest(files: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(_relative(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    arguments: list[str] = []
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
    for argument, default in zip(positional, defaults, strict=True):
        text = argument.arg
        if argument.annotation is not None:
            text += f": {ast.unparse(argument.annotation)}"
        if default is not None:
            text += f" = {ast.unparse(default)}"
        arguments.append(text)
    if node.args.vararg:
        arguments.append(f"*{node.args.vararg.arg}")
    elif node.args.kwonlyargs:
        arguments.append("*")
    for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
        text = argument.arg
        if argument.annotation is not None:
            text += f": {ast.unparse(argument.annotation)}"
        if default is not None:
            text += f" = {ast.unparse(default)}"
        arguments.append(text)
    if node.args.kwarg:
        arguments.append(f"**{node.args.kwarg.arg}")
    result = f"({', '.join(arguments)})"
    if node.returns is not None:
        result += f" -> {ast.unparse(node.returns)}"
    return result


def _symbol_rows(path: Path) -> list[str]:
    relative = _relative(path)
    try:
        tree = ast.parse(_read_text(path))
    except SyntaxError as exc:
        return [f"| `{relative}` | parse error | — | — | `{html.escape(str(exc))}` |"]

    rows: list[str] = []
    parents: list[str] = []

    def visit(nodes: list[ast.stmt]) -> None:
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                qualified = ".".join([*parents, node.name])
                doc = ast.get_docstring(node) or "No docstring."
                rows.append(
                    f"| `{relative}` | class | `{qualified}` | "
                    f"L{node.lineno}–L{node.end_lineno or node.lineno} | {html.escape(doc.splitlines()[0])} |"
                )
                parents.append(node.name)
                visit(node.body)
                parents.pop()
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = ".".join([*parents, node.name])
                kind = "async function" if isinstance(node, ast.AsyncFunctionDef) else "method" if parents else "function"
                doc = ast.get_docstring(node) or "No docstring."
                signature = html.escape(_signature(node))
                rows.append(
                    f"| `{relative}` | {kind} | `{qualified}{signature}` | "
                    f"L{node.lineno}–L{node.end_lineno or node.lineno} | {html.escape(doc.splitlines()[0])} |"
                )
                parents.append(node.name)
                visit(node.body)
                parents.pop()

    visit(tree.body)
    return rows


def _category(path: Path) -> str:
    relative = _relative(path)
    if relative.startswith("tests/"):
        return "automated test"
    if relative.startswith(".github/workflows/"):
        return "continuous integration"
    if path.name == "LICENSE":
        return "license"
    if path.name in {"pyproject.toml", "requirements.txt"}:
        return "packaging/dependencies"
    if path.name in {"README.md", "RUNBOOK.md"} or relative.startswith("docs/"):
        return "documentation"
    if relative.startswith("samples/"):
        return "safe sample fixture"
    if path.suffix == ".py":
        return "Python source"
    return "project configuration/resource"


def _line_note(path: Path, number: int, source: str) -> str:
    stripped = source.strip()
    if not stripped:
        return "Blank separator; keeps the surrounding source readable."
    if path.suffix == ".py":
        if stripped.startswith(('"""', "'''")):
            return "Documentation text describing the module, class, or callable."
        if stripped.startswith("from ") or stripped.startswith("import "):
            return "Dependency import used by this module."
        if stripped.startswith("class "):
            return "Class declaration; inspect the following indented block for its contract."
        if stripped.startswith(("def ", "async def ")):
            return "Callable declaration; its live location is captured by this generated reference."
        if stripped.startswith(("if ", "elif ", "else:", "match ", "case ")):
            return "Control-flow branch that selects behavior from current state or evidence."
        if stripped.startswith(("for ", "while ")):
            return "Iteration over a collection or repeated operation."
        if stripped.startswith("return"):
            return "Return boundary for the current callable."
        if stripped.startswith("raise "):
            return "Explicit failure boundary; callers or CLI handling should account for it."
        if stripped.startswith(("assert ", "with pytest.raises")):
            return "Test assertion or expected-error contract."
        if stripped.startswith("@"):
            return "Decorator that modifies the declaration immediately below."
        if "=" in stripped and not stripped.startswith(("#", "==")):
            return "Assignment or configuration value used by nearby logic."
        if stripped.startswith("#"):
            return "Maintainer comment explaining intent or context."
        return "Executable or structural Python line; interpret it with the surrounding block."
    if path.suffix in {".yml", ".yaml", ".toml"}:
        return "Configuration or metadata line consumed by project tooling."
    if path.suffix == ".json":
        return "Structured fixture or metadata line used as inert project data."
    if path.suffix == ".md":
        return "Project documentation line; verify volatile claims against code and tests."
    if path.name == "LICENSE":
        return "MIT license text defining reuse and distribution terms."
    if path.name == "Makefile":
        return "Development command or target used for repeatable local operations."
    return f"Repository text line from {_category(path)}."


def _inline_source(source: str) -> str:
    if not source:
        return "␠"
    escaped = html.escape(source, quote=False).replace("|", "&#124;")
    return f"<code>{escaped}</code>"


def generate() -> str:
    files = _repository_files()
    sources = _source_files(files)
    python_files = [path for path in sources if path.suffix == ".py"]
    source_line_count = sum(len(_read_text(path).splitlines()) for path in sources)
    content_digest = _digest(sources)

    output: list[str] = [
        "# MalForge Generated Code Reference",
        "",
        "> Generated from the live repository. **Do not hand-edit this file.**",
        f"> Generation date: {date.today().isoformat()}  ",
        f"> ATT&CK snapshot read from `core/constants.py`: `{_attack_version()}`  ",
        f"> Source-set SHA-256: `{content_digest}`  ",
        "> Regenerate after code changes: `python tools/generate_code_reference.py`",
        "",
        "This is a searchable engineering reference, not the interview study guide. Read "
        "`MALFORGE_HANDBOOK.md` for concepts, trade-offs, and placement answers. Use this "
        "file to locate symbols, inspect repository inventory, and study a specific source line.",
        "",
        "Line numbers below are generated snapshots. Regenerate before relying on them.",
        "",
        "## Part I — Live Python symbol catalog",
        "",
        "| File | Kind | Symbol/signature | Live lines | First docstring line |",
        "|---|---|---|---|---|",
    ]
    for path in python_files:
        output.extend(_symbol_rows(path))

    output.extend(
        [
            "",
            "## Part II — Repository file inventory",
            "",
            "| Path | Category | Bytes | Text lines |",
            "|---|---|---:|---:|",
        ]
    )
    for path in files:
        try:
            line_count = len(_read_text(path).splitlines())
        except OSError:
            line_count = 0
        output.append(
            f"| `{_relative(path)}` | {_category(path)} | {path.stat().st_size} | {line_count} |"
        )

    output.extend(
        [
            "",
            "## Part III — Generated line-by-line source guide",
            "",
            "Each source line has two physical reference lines: the exact escaped source and a short "
            "reading cue. Search for `path/to/file.py:L0055` to jump to a snapshot location.",
            "",
        ]
    )
    for path in sources:
        relative = _relative(path)
        lines = _read_text(path).splitlines()
        output.extend([f"### `{relative}`", ""])
        if not lines:
            output.extend(["- `(empty file)`", "  - Guide: This tracked file intentionally has no text content."])
            continue
        for number, source in enumerate(lines, start=1):
            anchor = f"{relative}:L{number:04d}"
            output.append(f"- `{anchor}` — {_inline_source(source)}")
            output.append(f"  - Guide: {_line_note(path, number, source)}")

    output.extend(
        [
            "",
            "## Part IV — Generation record",
            "",
            f"- Inventoried repository files: {len(files)}",
            f"- Parsed Python files: {len(python_files)}",
            f"- Guided source files: {len(sources)}",
            f"- Guided source lines: {source_line_count}",
            f"- Source-set SHA-256: `{content_digest}`",
            f"- ATT&CK version at generation: `{_attack_version()}`",
            "",
            "Before an interview, run:",
            "",
            "```powershell",
            "python -m pytest -q",
            'Select-String -Path core/constants.py -Pattern "ATTACK_VERSION"',
            "python tools/generate_code_reference.py",
            "```",
            "",
            "The pytest result belongs in the canonical testing snapshot in `MALFORGE_HANDBOOK.md`; "
            "it is intentionally not duplicated throughout this generated file.",
        ]
    )
    return "\n".join(output) + "\n"


def main() -> int:
    """Write the generated reference and report its physical line count."""
    rendered = generate()
    OUTPUT.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT} ({len(rendered.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
