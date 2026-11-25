/* NATXAJO · componentes reutilizables: paneles, indicadores, tablas, gráficos, estados vacíos y
   campos de formulario. Todos construyen nodos del DOM; ningún dato se interpreta como HTML. */
(() => {
  "use strict";

  const N = window.NATXAJO;
  const SVG_NS = "http://www.w3.org/2000/svg";

  function svgEl(etiqueta, atributos = {}, ...hijos) {
    const nodo = document.createElementNS(SVG_NS, etiqueta);
    for (const [clave, valor] of Object.entries(atributos)) {
      if (valor !== undefined && valor !== null) nodo.setAttribute(clave, String(valor));
    }
    for (const hijo of hijos) {
      nodo.append(typeof hijo === "string" ? document.createTextNode(hijo) : hijo);
    }
    return nodo;
  }

  N.cabeceraPagina = function cabeceraPagina({ titulo, descripcion = "", acciones = null }) {
    return N.el(
      "div",
      { class: "cabecera-pagina" },
      N.el(
        "div",
        null,
        N.el("h2", { class: "titulo-pagina", text: titulo }),
        descripcion ? N.el("p", { text: descripcion }) : null
      ),
      acciones ? N.el("div", { class: "acciones" }, acciones) : null
    );
  };

  N.panel = function panel({ titulo, sub = "", acciones = null, cuerpo, sinRelleno = false }) {
    return N.el(
      "section",
      { class: "panel" },
      N.el(
        "header",
        { class: "panel-cabecera" },
        N.el("div", null, N.el("h2", { text: titulo }), sub ? N.el("div", { class: "sub", text: sub }) : null),
        acciones ? N.el("div", { class: "acciones" }, acciones) : null
      ),
      N.el("div", { class: sinRelleno ? "panel-cuerpo sin-relleno" : "panel-cuerpo" }, cuerpo)
    );
  };

  N.kpi = function kpi({ etiqueta, valor, detalle = "", tono = "", icono = null }) {
    return N.el(
      "div",
      { class: `kpi ${tono}`.trim() },
      N.el("div", { class: "etiqueta-kpi", text: etiqueta }),
      N.el("div", { class: "valor" }, valor),
      detalle ? N.el("div", { class: "detalle", text: detalle }) : null,
      icono ? N.icono(icono) : null
    );
  };

  N.badge = function badge(texto, tono = "neutro") {
    return N.el("span", { class: `badge ${tono}`, text: texto });
  };

  N.estadoPlugin = function estadoPlugin(plugin) {
    if (plugin.cuarentena) return N.badge("En cuarentena", "peligro");
    if (plugin.habilitado) return N.badge("Habilitado", "ok");
    return N.badge("Deshabilitado", "neutro");
  };

  N.estadoModulo = function estadoModulo(modulo) {
    if (modulo.problemas && modulo.problemas.length) return N.badge("Con problemas", "aviso");
    return modulo.habilitado ? N.badge("Habilitado", "ok") : N.badge("Deshabilitado", "neutro");
  };

  N.gravedad = function gravedad(valor) {
    const mapa = {
      alta: ["Alta", "peligro"],
      media: ["Media", "aviso"],
      baja: ["Baja", "info"],
    };
    const [texto, tono] = mapa[valor] || [N.texto(valor), "neutro"];
    return N.badge(texto, tono);
  };

  N.estadoComprobacion = function estadoComprobacion(valor) {
    const texto = N.texto(valor);
    const minusculas = texto.toLowerCase();
    if (/ok|correct|sano|cumpl/.test(minusculas)) return N.badge(texto, "ok");
    if (/aviso|advert|pendient/.test(minusculas)) return N.badge(texto, "aviso");
    if (/error|fall|critic|no cumpl/.test(minusculas)) return N.badge(texto, "peligro");
    return N.badge(texto, "neutro");
  };

  N.estadoCuenta = function estadoCuenta(valor) {
    if (valor === "active") return N.badge("Activa", "ok");
    if (valor === "disabled") return N.badge("Deshabilitada", "peligro");
    return N.badge(N.texto(valor), "neutro");
  };

  N.chips = function chips(lista) {
    const valores = Array.isArray(lista) ? lista : [];
    if (!valores.length) return N.el("span", { class: "muted", text: "Ninguno" });
    return N.el("div", { class: "chips" }, valores.map((valor) => N.el("span", { class: "chip", text: valor })));
  };

  N.alerta = function alerta(tono, texto, icono = "alerta") {
    return N.el("div", { class: `alerta ${tono}`, role: tono === "peligro" ? "alert" : "note" }, N.icono(icono), N.el("span", { text: texto }));
  };

  N.vacio = function vacio({ icono = "vacio", titulo, texto = "", accion = null }) {
    return N.el(
      "div",
      { class: "vacio" },
      N.icono(icono, "icono-grande"),
      N.el("strong", { text: titulo }),
      texto ? N.el("p", { text: texto }) : null,
      accion
    );
  };

  N.seccionNoDisponible = function seccionNoDisponible(seccion) {
    return N.vacio({
      icono: "candado",
      titulo: "Sin acceso a esta sección",
      texto: seccion && seccion.motivo ? seccion.motivo : "Su cuenta no puede ver estos datos.",
    });
  };

  N.esqueleto = function esqueleto(lineas = 4) {
    const nodo = N.el("div", { class: "esqueleto", "aria-busy": "true", role: "status" });
    for (let indice = 0; indice < lineas; indice += 1) {
      const linea = N.el("span");
      linea.style.width = `${96 - indice * 13}%`;
      nodo.append(linea);
    }
    return nodo;
  };

  N.ficha = function ficha(pares) {
    return N.el(
      "dl",
      { class: "ficha" },
      pares.flatMap(([etiqueta, valor]) => [
        N.el("dt", { text: etiqueta }),
        N.el("dd", null, valor instanceof Node ? valor : N.texto(valor)),
      ])
    );
  };

  N.campo = function campo({ id, etiqueta, tipo = "text", valor = "", opciones = null, ayuda = "", ancho = false, ...atributos }) {
    const control = opciones
      ? N.el(
          "select",
          { id, name: id, ...atributos },
          opciones.map((opcion) =>
            N.el("option", { value: opcion.valor, selected: opcion.valor === valor ? true : null, text: opcion.texto })
          )
        )
      : N.el("input", { id, name: id, type: tipo, value: valor, ...atributos });
    return N.el(
      "div",
      { class: ancho ? "campo ancho" : "campo" },
      N.el("label", { for: id, text: etiqueta }),
      control,
      ayuda ? N.el("span", { class: "ayuda", text: ayuda }) : null
    );
  };

  N.pestanas = function pestanas(items, actual, alCambiar) {
    return N.el(
      "div",
      { class: "pestanas", role: "tablist" },
      items.map((item) =>
        N.el("button", {
          class: "pestana",
          type: "button",
          role: "tab",
          "aria-selected": String(item.id === actual),
          text: item.titulo,
          onclick: () => alCambiar(item.id),
        })
      )
    );
  };

  /* ---- Tablas ------------------------------------------------------------------------------- */

  function textoDeCelda(columna, fila) {
    if (columna.texto) return String(columna.texto(fila));
    return N.texto(fila[columna.clave]);
  }

  function valorDeOrden(columna, fila) {
    if (columna.valor) return columna.valor(fila);
    return fila[columna.clave];
  }

  function comparar(a, b) {
    if (a === b) return 0;
    if (a === undefined || a === null || a === "") return 1;
    if (b === undefined || b === null || b === "") return -1;
    if (typeof a === "number" && typeof b === "number") return a - b;
    if (typeof a === "boolean" && typeof b === "boolean") return Number(a) - Number(b);
    return String(a).localeCompare(String(b), "es", { numeric: true, sensitivity: "base" });
  }

  /* columnas: [{clave, titulo, render?, texto?, valor?, envolver?, ordenable?}]
     seleccion: {activa(fila) -> boolean, alElegir(fila)} */
  N.tabla = function tabla({
    id,
    columnas,
    filas,
    vacio = null,
    buscar = true,
    placeholder = "Buscar en la tabla…",
    seleccion = null,
  }) {
    const estado = N.estadoTabla(id);
    const cabecera = N.el("thead");
    const cuerpo = N.el("tbody");
    const pie = N.el("div", { class: "pie-tabla", role: "status" });
    const visibles = () => {
      const filtro = estado.filtro.trim().toLowerCase();
      let lista = filas;
      if (filtro) {
        lista = lista.filter((fila) => columnas.some((col) => textoDeCelda(col, fila).toLowerCase().includes(filtro)));
      }
      const columna = columnas.find((col) => col.clave === estado.clave);
      if (columna && columna.ordenable !== false) {
        const sentido = estado.dir === "asc" ? 1 : -1;
        lista = [...lista].sort((a, b) => comparar(valorDeOrden(columna, a), valorDeOrden(columna, b)) * sentido);
      }
      return lista;
    };
    const pintarCabecera = () => {
      cabecera.replaceChildren(
        N.el(
          "tr",
          null,
          columnas.map((col) => {
            if (col.ordenable === false) return N.el("th", { scope: "col", text: col.titulo });
            const activa = estado.clave === col.clave;
            return N.el(
              "th",
              { scope: "col", "aria-sort": activa ? (estado.dir === "asc" ? "ascending" : "descending") : "none" },
              N.el("button", {
                class: "ordenable",
                type: "button",
                "data-orden": activa ? estado.dir : null,
                text: col.titulo,
                onclick: () => {
                  if (estado.clave === col.clave) {
                    estado.dir = estado.dir === "asc" ? "desc" : "asc";
                  } else {
                    estado.clave = col.clave;
                    estado.dir = "asc";
                  }
                  pintarCabecera();
                  pintarCuerpo();
                },
              })
            );
          })
        )
      );
    };
    const pintarCuerpo = () => {
      const lista = visibles();
      if (!lista.length) {
        const sinFiltro = !estado.filtro.trim();
        cuerpo.replaceChildren(
          N.el(
            "tr",
            null,
            N.el(
              "td",
              { colspan: String(columnas.length) },
              sinFiltro && filas.length === 0
                ? vacio || N.vacio({ titulo: "Sin registros", texto: "No hay datos que mostrar." })
                : N.vacio({ icono: "buscar", titulo: "Sin coincidencias", texto: "Pruebe con otro texto o quite los filtros." })
            )
          )
        );
      } else {
        cuerpo.replaceChildren(
          ...lista.map((fila) => {
            const activa = seleccion ? seleccion.activa(fila) : false;
            const attrs = seleccion
              ? {
                  class: "seleccionable",
                  tabindex: "0",
                  "aria-selected": String(activa),
                  onclick: () => seleccion.alElegir(fila),
                  onkeydown: (evento) => {
                    if (evento.key === "Enter" || evento.key === " ") {
                      evento.preventDefault();
                      seleccion.alElegir(fila);
                    }
                  },
                }
              : null;
            return N.el(
              "tr",
              attrs,
              columnas.map((col) =>
                N.el(
                  "td",
                  { class: col.envolver ? "envolver" : null },
                  col.render ? col.render(fila) : textoDeCelda(col, fila)
                )
              )
            );
          })
        );
      }
      pie.textContent = `${N.numero(lista.length)} de ${N.numero(filas.length)} registros`;
    };
    const entradaBusqueda = buscar
      ? N.el(
          "div",
          { class: "barra-herramientas" },
          N.el(
            "div",
            { class: "buscador" },
            N.icono("buscar"),
            N.el("input", {
              type: "search",
              placeholder,
              "aria-label": "Buscar en la tabla",
              value: estado.filtro,
              oninput: (evento) => {
                estado.filtro = evento.target.value;
                pintarCuerpo();
              },
            })
          )
        )
      : null;
    pintarCabecera();
    pintarCuerpo();
    const bloque = N.el(
      "div",
      { class: "tabla-bloque" },
      entradaBusqueda,
      N.el("div", { class: "tabla-envoltura" }, N.el("table", { class: "tabla" }, cabecera, cuerpo)),
      N.el("div", { class: "pie-tabla" }, pie)
    );
    // Permite repintar solo las filas (p. ej. al cambiar la selección) sin perder el foco.
    bloque.refrescarFilas = pintarCuerpo;
    return bloque;
  };

  /* ---- Gráficos ----------------------------------------------------------------------------- */

  N.dona = function dona(segmentos, { total, etiqueta }) {
    const suma = segmentos.reduce((acumulado, segmento) => acumulado + segmento.valor, 0);
    const radio = 52;
    const circunferencia = 2 * Math.PI * radio;
    const grafico = svgEl("svg", { viewBox: "0 0 140 140", role: "img", "aria-label": `${etiqueta}: ${suma}` });
    grafico.append(svgEl("circle", { class: "pista", cx: 70, cy: 70, r: radio }));
    let acumulado = 0;
    for (const segmento of segmentos) {
      if (segmento.valor <= 0 || suma === 0) continue;
      const longitud = (segmento.valor / suma) * circunferencia;
      grafico.append(
        svgEl("circle", {
          class: `seg tono-${segmento.tono || "neutro"}`,
          cx: 70,
          cy: 70,
          r: radio,
          "stroke-dasharray": `${longitud} ${circunferencia - longitud}`,
          "stroke-dashoffset": -acumulado,
          transform: "rotate(-90 70 70)",
        })
      );
      acumulado += longitud;
    }
    grafico.append(
      svgEl("text", { class: "total", x: 70, y: 74 }, N.numero(total !== undefined ? total : suma)),
      svgEl("text", { class: "total-etiqueta", x: 70, y: 92 }, etiqueta)
    );
    return N.el(
      "div",
      { class: "dona" },
      grafico,
      N.el(
        "div",
        { class: "leyenda" },
        segmentos.map((segmento) =>
          N.el(
            "div",
            { class: "leyenda-fila" },
            N.el("span", { class: `muestra tono-${segmento.tono || "neutro"}` }),
            N.el("span", { text: segmento.etiqueta }),
            N.el("span", { class: "muted mono", text: N.numero(segmento.valor) })
          )
        )
      )
    );
  };

  N.barras = function barras(items) {
    const maximo = Math.max(1, ...items.map((item) => item.valor));
    return N.el(
      "div",
      { class: "barras" },
      items.map((item) => {
        const valor = N.el("div", { class: item.tono ? `barra-valor tono-${item.tono}` : "barra-valor" });
        valor.style.width = `${Math.max(2, (item.valor / maximo) * 100)}%`;
        return N.el(
          "div",
          { class: "barra-fila" },
          N.el("span", { class: "etiqueta-barra", title: item.etiqueta, text: item.etiqueta }),
          N.el("div", { class: "barra-pista" }, valor),
          N.el("span", { class: "muted mono", text: N.numero(item.valor) })
        );
      })
    );
  };

  /* Sección no disponible o carga: pinta un bloque según el estado del dato. */
  N.pintar = function pintar(contenedor, nodos) {
    const lista = [nodos]
      .flat(Infinity)
      .filter((nodo) => nodo !== null && nodo !== undefined && nodo !== false);
    contenedor.replaceChildren(...lista);
  };
})();
