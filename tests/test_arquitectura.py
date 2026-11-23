"""Arquitectura verificada con AST: capas, contratos, ciclos y ejecución dinámica.

Las reglas están en docs/arquitectura.md. Estas pruebas leen el código fuente con `ast` y no
importan ningún módulo de la plataforma. Cada analizador tiene una prueba que demuestra que
detecta una infracción de muestra, para que un analizador roto no deje las reglas sin comprobar.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = ROOT / "src" / "natxajo_auditor"
PACKAGE = "natxajo_auditor"
ROOT_PACKAGE = "(raiz)"
COMPOSITION = "natxajo_auditor.kernel.composition"

# Paquetes que cada capa puede importar, en tiempo de ejecución o solo para anotaciones.
ALLOWED: dict[str, frozenset[str]] = {
    "core": frozenset(),
    "storage": frozenset({"core"}),
    "configuration": frozenset({"core", "storage"}),
    "versioning": frozenset({"core", "storage"}),
    "security": frozenset({"core", "storage"}),
    "modules": frozenset({"core", "storage"}),
    "plugins": frozenset({"core", "storage"}),
    "auditing": frozenset({"core", "storage"}),
    "reporting": frozenset({"auditing", "core", "storage"}),
    "maintenance": frozenset({"core", "storage"}),
    "kernel": frozenset(
        {
            "auditing",
            "configuration",
            "core",
            "maintenance",
            "modules",
            "plugins",
            "reporting",
            "security",
            "storage",
            "versioning",
        }
    ),
    "interfaces": frozenset({"core", "kernel"}),
    ROOT_PACKAGE: frozenset({"core", "kernel", "interfaces"}),
}
PACKAGES = frozenset(ALLOWED) - {ROOT_PACKAGE}
# Subsistemas concretos: solo la composición del núcleo puede importarlos en tiempo de ejecución.
SUBSYSTEMS = frozenset(
    {
        "auditing",
        "configuration",
        "maintenance",
        "modules",
        "plugins",
        "reporting",
        "security",
        "storage",
        "versioning",
    }
)
# Módulos que poseen una función de hash. Son las únicas rutas (relativas a src) que importan hashlib.
HASH_OWNERS = frozenset({"core/utilities.py", "core/ed25519.py", "security/passwords.py"})
DYNAMIC_PACKAGES = frozenset({"modules", "plugins"})
FORBIDDEN_MODULES = frozenset(
    {
        "builtins",
        "code",
        "codeop",
        "ctypes",
        "imp",
        "importlib",
        "marshal",
        "multiprocessing",
        "pickle",
        "pkgutil",
        "runpy",
        "shelve",
        "subprocess",
    }
)
FORBIDDEN_CALLS = frozenset({"__import__", "breakpoint", "compile", "eval", "exec"})
# `re.compile` es legítimo, así que compile solo se prohíbe como función suelta.
FORBIDDEN_ATTRIBUTE_CALLS = frozenset({"__import__", "eval", "exec"})
FORBIDDEN_OS_PREFIXES = ("exec", "fork", "kill", "popen", "spawn", "system")
# Rutas relativas a src/natxajo_auditor con ejecución dinámica autorizada. Vacía: no hay ninguna.
# Añadir una entrada exige revisión de seguridad y una justificación en docs/arquitectura.md.
AUTHORIZED_DYNAMIC: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Edge:
    target: str
    line: int
    type_only: bool


def module_of(relative: Path) -> str:
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join([PACKAGE, *parts])


def package_of(module: str) -> str:
    parts = module.split(".")
    if len(parts) > 1 and parts[1] in PACKAGES:
        return parts[1]
    return ROOT_PACKAGE


def _is_type_checking(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _inside_package(name: str) -> bool:
    return name == PACKAGE or name.startswith(PACKAGE + ".")


def edges_in(source: str) -> list[Edge]:
    """Importaciones internas de un módulo. `from pkg import x` añade `pkg` y `pkg.x`."""
    tree = ast.parse(source)
    type_only: set[int] = set()
    for node in ast.walk(tree):
        if _is_type_checking(node):
            type_only.update(id(child) for child in ast.walk(node))
    edges: list[Edge] = []
    for node in ast.walk(tree):
        flag = id(node) in type_only
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _inside_package(alias.name):
                    edges.append(Edge(alias.name, node.lineno, flag))
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module
            and _inside_package(node.module)
        ):
            edges.append(Edge(node.module, node.lineno, flag))
            for alias in node.names:
                edges.append(Edge(f"{node.module}.{alias.name}", node.lineno, flag))
    return edges


def relative_imports_in(source: str) -> list[int]:
    return [
        node.lineno
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.level > 0
    ]


def imported_roots(source: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def layer_violations(edges_by_module: dict[str, list[Edge]]) -> list[str]:
    found: list[str] = []
    for module, edges in sorted(edges_by_module.items()):
        origin = package_of(module)
        for edge in edges:
            target = package_of(edge.target)
            if target in (origin, ROOT_PACKAGE) or target in ALLOWED[origin]:
                continue
            found.append(f"{module}:{edge.line} -> {edge.target}")
    return found


def dynamic_findings(source: str) -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    found.append(f"línea {line}: importa {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module.split(".")[0] in FORBIDDEN_MODULES:
                found.append(f"línea {line}: importa desde {node.module}")
            if node.module == "os":
                for alias in node.names:
                    if alias.name.startswith(FORBIDDEN_OS_PREFIXES):
                        found.append(f"línea {line}: importa os.{alias.name}")
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_CALLS:
            found.append(f"línea {line}: usa {node.id}")
        elif isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_ATTRIBUTE_CALLS:
                found.append(f"línea {line}: usa {node.attr}")
            elif (
                isinstance(node.value, ast.Name)
                and node.value.id == "os"
                and node.attr.startswith(FORBIDDEN_OS_PREFIXES)
            ):
                found.append(f"línea {line}: usa os.{node.attr}")
    return found


def cast_findings(source: str) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Name) and func.id == "cast") or (
                isinstance(func, ast.Attribute) and func.attr == "cast"
            ):
                lines.append(node.lineno)
    return lines


def find_cycle(graph: dict[str, set[str]]) -> list[str] | None:
    done: set[str] = set()
    path: list[str] = []

    def visit(node: str) -> list[str] | None:
        if node in path:
            return [*path[path.index(node) :], node]
        if node in done:
            return None
        path.append(node)
        for following in sorted(graph.get(node, ())):
            cycle = visit(following)
            if cycle is not None:
                return cycle
        path.pop()
        done.add(node)
        return None

    for node in sorted(graph):
        cycle = visit(node)
        if cycle is not None:
            return cycle
    return None


def _source_files() -> dict[str, tuple[str, str]]:
    """Módulo -> (ruta relativa a src, texto) de cada archivo del paquete."""
    files: dict[str, tuple[str, str]] = {}
    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        relative = path.relative_to(PACKAGE_DIR)
        if "__pycache__" in relative.parts:
            continue
        files[module_of(relative)] = (relative.as_posix(), path.read_text(encoding="utf-8"))
    return files


def _edges() -> dict[str, list[Edge]]:
    return {module: edges_in(text) for module, (_, text) in _source_files().items()}


# --- Pruebas sobre el código real ------------------------------------------------------------


def test_every_package_has_a_declared_layer() -> None:
    found = {p.name for p in PACKAGE_DIR.iterdir() if p.is_dir() and p.name != "__pycache__"}
    assert found == PACKAGES, "paquete sin capa declarada, o capa declarada sin paquete"


def test_each_package_imports_only_what_its_layer_allows() -> None:
    assert layer_violations(_edges()) == []


def test_interfaces_do_not_import_security() -> None:
    touched = {
        package_of(edge.target)
        for module, edges in _edges().items()
        if package_of(module) == "interfaces"
        for edge in edges
    }
    assert "security" not in touched


def test_modules_and_plugins_depend_only_on_core_and_storage() -> None:
    for module, edges in _edges().items():
        origin = package_of(module)
        if origin not in DYNAMIC_PACKAGES:
            continue
        allowed = {origin, "core", "storage", ROOT_PACKAGE}
        extra = {package_of(edge.target) for edge in edges} - allowed
        assert not extra, f"{module} importa {sorted(extra)}"


def test_only_the_composition_module_imports_subsystems_at_runtime() -> None:
    offenders: list[str] = []
    for module, edges in _edges().items():
        if package_of(module) != "kernel" or module == COMPOSITION:
            continue
        offenders += [
            f"{module}:{edge.line} -> {edge.target}"
            for edge in edges
            if not edge.type_only and package_of(edge.target) in SUBSYSTEMS
        ]
    assert offenders == []


def test_the_kernel_does_not_use_cast() -> None:
    offenders = [
        f"{rel}:{line}"
        for module, (rel, text) in _source_files().items()
        if package_of(module) == "kernel"
        for line in cast_findings(text)
    ]
    assert offenders == []


def test_relative_imports_are_not_used() -> None:
    offenders = [
        f"{rel}:{line}"
        for rel, text in _source_files().values()
        for line in relative_imports_in(text)
    ]
    assert offenders == []


def test_the_module_graph_has_no_import_cycles() -> None:
    files = _source_files()
    graph = {
        module: {edge.target for edge in edges_in(text) if edge.target in files}
        for module, (_, text) in files.items()
    }
    cycle = find_cycle(graph)
    assert cycle is None, " -> ".join(cycle or [])


def test_modules_and_plugins_do_not_execute_dynamic_code() -> None:
    offenders: list[str] = []
    for module, (rel, text) in _source_files().items():
        if package_of(module) not in DYNAMIC_PACKAGES or rel in AUTHORIZED_DYNAMIC:
            continue
        offenders += [f"{rel} {finding}" for finding in dynamic_findings(text)]
    assert offenders == []


def test_hash_primitives_live_in_their_owner_modules() -> None:
    offenders = [
        rel
        for rel, text in _source_files().values()
        if "hashlib" in imported_roots(text) and rel not in HASH_OWNERS
    ]
    assert offenders == []


def test_the_documented_dependency_table_matches_the_enforced_rules() -> None:
    text = (ROOT / "docs" / "arquitectura.md").read_text(encoding="utf-8")
    section = text.split("## Reglas de dependencia", 1)[1].split("\n## ", 1)[0]
    documented: dict[str, set[str]] = {}
    for line in section.splitlines():
        if not line.startswith("| `"):
            continue
        name, allowed = [cell.strip() for cell in line.strip("|").split("|")]
        documented[name.strip("`")] = set(re.findall(r"`([^`]+)`", allowed))
    assert documented == {name: set(allowed) for name, allowed in ALLOWED.items()}


# --- Pruebas de los analizadores: cada uno debe detectar su infracción de muestra ------------


def test_the_analyzer_detects_a_layer_violation() -> None:
    source = "from natxajo_auditor.security.service import SecurityService\n"
    assert layer_violations({"natxajo_auditor.interfaces.terminal.app": edges_in(source)})


def test_the_analyzer_marks_type_only_imports() -> None:
    source = (
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from natxajo_auditor.security.service import SecurityService\n"
    )
    edges = edges_in(source)
    assert edges
    assert all(edge.type_only for edge in edges)


def test_the_analyzer_detects_dynamic_execution() -> None:
    source = "import importlib\nvalor = eval('1')\nimport re\npatron = re.compile('a')\n"
    findings = dynamic_findings(source)
    assert any("importlib" in finding for finding in findings)
    assert any("eval" in finding for finding in findings)
    assert not any("compile" in finding for finding in findings)


def test_the_analyzer_detects_cycles() -> None:
    assert find_cycle({"a": {"b"}, "b": {"c"}, "c": {"a"}}) is not None
    assert find_cycle({"a": {"b"}, "b": set()}) is None


def test_the_analyzer_detects_cast() -> None:
    assert cast_findings("from typing import cast\nvalor = cast(int, x)\n") == [2]
