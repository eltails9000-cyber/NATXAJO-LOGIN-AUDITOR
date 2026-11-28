"""Motor de ejecución: aplica los límites a cada petición y produce un resultado por caso.

Controles: presupuesto total de solicitudes, concurrencia, pausa entre peticiones y cancelación.
Cada resultado se entrega al sumidero en el momento en que se produce, de modo que el servicio lo
persiste aunque la ejecución falle después. Un caso que no puede completarse queda SKIPPED con su
motivo, nunca como PASS.
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from natxajo_auditor.pruebas.clasificacion import clasificar, evaluar
from natxajo_auditor.pruebas.cliente import (
    CambioDnsError,
    ClienteHttp,
    InformeTls,
    Respuesta,
    Sesion,
)
from natxajo_auditor.pruebas.formulario import campos_ocultos, construir_campos
from natxajo_auditor.pruebas.modelo import (
    Caso,
    Formulario,
    Limites,
    Resultado,
    ResultadoCaso,
)


class Detenida(Exception):
    """La ejecución no puede seguir: se agotó el presupuesto o el operador canceló."""

    def __init__(self, motivo: str) -> None:
        super().__init__(motivo)
        self.motivo = motivo


class FalloTecnico(Exception):
    """Un paso no pudo completarse por un problema técnico o de configuración del objetivo."""

    def __init__(self, motivo: str) -> None:
        super().__init__(motivo)
        self.motivo = motivo


class Presupuesto:
    """Contador compartido de solicitudes. Reservar es atómico: no se supera el máximo en hilos."""

    def __init__(self, maximo: int) -> None:
        self._maximo = maximo
        self._usadas = 0
        self._cerrojo = threading.Lock()

    def reservar(self) -> bool:
        with self._cerrojo:
            if self._usadas >= self._maximo:
                return False
            self._usadas += 1
            return True

    @property
    def usadas(self) -> int:
        with self._cerrojo:
            return self._usadas


@dataclass(frozen=True)
class Contexto:
    cliente: ClienteHttp
    limites: Limites
    presupuesto: Presupuesto
    cancelacion: threading.Event
    # Destino de cada resultado en cuanto se produce. None en pruebas que no persisten nada.
    sumidero: Callable[[ResultadoCaso], None] | None = None

    def reservar(self) -> None:
        """Comprueba la cancelación y reserva una solicitud del presupuesto."""
        if self.cancelacion.is_set():
            raise Detenida("ejecución cancelada por el operador")
        if not self.presupuesto.reservar():
            raise Detenida("presupuesto de solicitudes agotado")

    def peticion(
        self,
        metodo: str,
        ruta: str,
        campos: dict[str, str] | None,
        sesion: Sesion,
    ) -> Respuesta:
        """Envía una petición si quedan presupuesto y tiempo. Respeta la pausa configurada."""
        self.reservar()
        try:
            respuesta = self.cliente.enviar(metodo, ruta, campos, sesion)
        except CambioDnsError:
            self.cancelacion.set()
            raise
        if self.limites.pausa_ms > 0:
            self.cancelacion.wait(self.limites.pausa_ms / 1000)
        return respuesta

    def informe_tls(self) -> InformeTls:
        """Conexión TLS de comprobación. Cuenta como una solicitud del presupuesto."""
        self.reservar()
        try:
            return self.cliente.informe_tls()
        except CambioDnsError:
            self.cancelacion.set()
            raise

    def emitir(self, resultado: ResultadoCaso) -> None:
        if self.sumidero is not None:
            self.sumidero(resultado)


def anotar(contexto: Contexto, resultados: list[ResultadoCaso], resultado: ResultadoCaso) -> None:
    """Añade un resultado a la lista de la ejecución y lo entrega al sumidero en el mismo instante."""
    resultados.append(resultado)
    contexto.emitir(resultado)


def obtener_token(formulario: Formulario, contexto: Contexto, sesion: Sesion) -> str | None:
    """Token CSRF de la página del formulario, o None si el formulario no lo declara."""
    if formulario.csrf is None:
        return None
    respuesta = contexto.peticion("GET", formulario.csrf.pagina, None, sesion)
    if respuesta.error is not None or not 200 <= respuesta.codigo < 300:
        motivo = respuesta.error or f"HTTP {respuesta.codigo}"
        raise FalloTecnico(f"no se pudo leer la página del formulario ({motivo})")
    token = campos_ocultos(respuesta.cuerpo).get(formulario.csrf.campo)
    if token is None:
        raise FalloTecnico("la página no incluye el campo CSRF configurado")
    return token


def ejecutar_casos(casos: Sequence[Caso], contexto: Contexto) -> list[ResultadoCaso]:
    """Ejecuta los casos con la concurrencia configurada.

    Los resultados se entregan en el orden de entrada aunque se ejecuten en paralelo. Un error
    inesperado se propaga: los resultados ya entregados quedan persistidos.
    """
    resultados: list[ResultadoCaso] = []
    if contexto.limites.concurrencia <= 1:
        for caso in casos:
            anotar(contexto, resultados, _caso(caso, contexto))
    else:
        with ThreadPoolExecutor(max_workers=contexto.limites.concurrencia) as grupo:
            pendientes = [grupo.submit(_caso, caso, contexto) for caso in casos]
            for pendiente in pendientes:
                anotar(contexto, resultados, pendiente.result())
    return numerar(resultados)


def numerar(resultados: Sequence[ResultadoCaso]) -> list[ResultadoCaso]:
    return [dataclasses.replace(r, posicion=i) for i, r in enumerate(resultados, start=1)]


def resultado_de(
    formulario: Formulario,
    caso_id: str,
    cuenta: str | None,
    esperado: str,
    resultado: Resultado,
    observado: str,
    motivo: str,
    respuesta: Respuesta | None = None,
) -> ResultadoCaso:
    codigo = respuesta.codigo if respuesta is not None and respuesta.codigo > 0 else None
    return ResultadoCaso(
        posicion=0,
        caso_id=caso_id,
        formulario_id=formulario.id,
        tipo=formulario.tipo.value,
        cuenta=cuenta,
        resultado=resultado,
        esperado=esperado,
        observado=observado,
        codigo_http=codigo,
        duracion_ms=respuesta.duracion_ms if respuesta is not None else None,
        motivo=motivo,
    )


def interrupcion(
    formulario: Formulario,
    caso_id: str,
    cuenta: str | None,
    exc: Detenida | FalloTecnico,
) -> ResultadoCaso:
    """Resultado de un caso que no pudo completarse: SKIPPED si se detuvo, ERROR si falló."""
    if isinstance(exc, Detenida):
        return resultado_de(formulario, caso_id, cuenta, "-", Resultado.SKIPPED, "", exc.motivo)
    return resultado_de(formulario, caso_id, cuenta, "-", Resultado.ERROR, "error", exc.motivo)


def _caso(caso: Caso, contexto: Contexto) -> ResultadoCaso:
    formulario = caso.formulario
    sesion = Sesion()
    try:
        token = obtener_token(formulario, contexto, sesion)
        campos = construir_campos(
            formulario,
            identidad=caso.identidad,
            contrasena=caso.contrasena,
            token=token,
        )
        respuesta = contexto.peticion("POST", formulario.ruta, campos, sesion)
    except (Detenida, FalloTecnico) as exc:
        return interrupcion(formulario, caso.id, caso.cuenta, exc)
    observado, motivo = clasificar(respuesta, formulario.reglas)
    resultado, detalle = evaluar(caso.esperado, observado, motivo)
    return resultado_de(
        formulario,
        caso.id,
        caso.cuenta,
        caso.esperado.value,
        resultado,
        observado.value,
        detalle,
        respuesta,
    )
