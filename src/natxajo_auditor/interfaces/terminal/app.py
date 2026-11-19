from pathlib import Path

from natxajo_auditor.kernel.bootstrap import create_context
from natxajo_auditor.kernel.kernel import Kernel


def run_terminal() -> int:
    root = Path.cwd()
    kernel = Kernel(create_context(root))
    kernel.startup()

    try:
        print("NATXAJO-LOGIN-AUDITOR")
        print("1. Estado")
        print("2. Versiones")
        print("3. Cargar versión 0.1.0")
        print("0. Salir")

        while True:
            choice = input("\nSeleccione una opción: ").strip()
            if choice == "1":
                print(kernel.health())
            elif choice == "2":
                manager = kernel.container.get("versions")
                for item in manager.registry.available():
                    print(f"- {item.version} | {item.channel} | kernel {item.compatible_kernel}")
            elif choice == "3":
                try:
                    print("Versión activa:", manager.load("0.1.0"))
                except Exception as exc:
                    print(f"Error: {exc}")
            elif choice == "0":
                break
            else:
                print("Opción no válida")
    finally:
        kernel.shutdown()
    return 0
