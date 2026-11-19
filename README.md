# NATXAJO-LOGIN-AUDITOR

Plataforma modular de auditoría defensiva de autenticación para Windows.

Solo debe utilizarse en sistemas propios o con autorización verificable. No incluye fuerza bruta, credential stuffing, adivinación de contraseñas, evasión de controles ni recolección de credenciales reales.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
python main.py
```

## Estado

Versión inicial implementada: núcleo, configuración, almacenamiento SQLite, registro de versiones, terminal y pruebas básicas. Los subsistemas avanzados se desarrollan por fases y se marcarán como pendientes hasta contar con pruebas verificadas.
