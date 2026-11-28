"""Credenciales de las cuentas sintéticas y su identidad en cada formulario.

Las contraseñas y los códigos MFA de prueba se leen del entorno en el momento de la ejecución. No
se escriben en configuración, base de datos, registros ni informes, y las excepciones nombran la
variable que falta, nunca su valor.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.pruebas.modelo import Credencial, CuentaSintetica, Formulario, TipoFormulario


def resolver_credenciales(
    cuentas: Sequence[CuentaSintetica],
    entorno: Mapping[str, str],
    *,
    con_mfa: bool,
) -> dict[str, Credencial]:
    """Credenciales de cada cuenta leídas del entorno. Falla antes de enviar nada si falta alguna."""
    resultado: dict[str, Credencial] = {}
    for cuenta in cuentas:
        contrasena = entorno.get(cuenta.variable_contrasena, "")
        if not contrasena:
            raise ValidationError(
                f"falta la variable de entorno {cuenta.variable_contrasena} "
                f"de la cuenta sintética '{cuenta.id}'"
            )
        codigo: str | None = None
        if con_mfa:
            if cuenta.variable_mfa is None:
                raise ValidationError(f"la cuenta sintética '{cuenta.id}' no declara variable_mfa")
            codigo = entorno.get(cuenta.variable_mfa, "")
            if not codigo:
                raise ValidationError(
                    f"falta la variable de entorno {cuenta.variable_mfa} "
                    f"del código MFA de la cuenta '{cuenta.id}'"
                )
        resultado[cuenta.id] = Credencial(
            usuario=cuenta.usuario,
            contrasena=contrasena,
            correo=cuenta.correo,
            codigo_mfa=codigo,
        )
    return resultado


def identidad_de(formulario: Formulario, credencial: Credencial) -> str:
    """Valor del campo de identidad: el correo en los formularios de correo, el usuario en el resto."""
    if formulario.tipo is TipoFormulario.CORREO_CONTRASENA:
        if credencial.correo is None:
            raise ValidationError(
                "la cuenta sintética no declara correo para un formulario de correo"
            )
        return credencial.correo
    return credencial.usuario
