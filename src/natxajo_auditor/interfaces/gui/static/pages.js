/* NATXAJO · páginas. Cada página se registra con su título, su icono y su función render. Los datos
   vienen de la API; las acciones de cambio pasan por confirmación y, si hace falta, por la
   reautenticación de la sesión. */
(() => {
  "use strict";

  const N = window.NATXAJO;
  const orden = [];
  N.paginas = {};

  function registrar(id, definicion) {
    N.paginas[id] = Object.assign({ id }, definicion);
    orden.push(id);
  }

  N.listaPaginas = () => orden.map((id) => N.paginas[id]);

  /* ---- utilidades -------------------------------------------------------------------------- */

  function esSesionCaducada(fallo) {
    return fallo && (fallo.codigo === "sesion" || fallo.codigo === "no_autenticado");
  }

  /* Carga datos en una zona. Si llega otra carga mientras tanto, la respuesta antigua se descarta. */
  async function cargarEn(zona, cargador, construir) {
    zona.__carga = (zona.__carga || 0) + 1;
    const turno = zona.__carga;
    N.pintar(zona, N.esqueleto(5));
    try {
      const datos = await cargador();
      if (zona.__carga !== turno) return;
      const nodos = construir(datos);
      // Algunos constructores pintan la zona ellos mismos y no devuelven nada.
      if (nodos !== undefined) N.pintar(zona, nodos);
    } catch (fallo) {
      if (zona.__carga !== turno || esSesionCaducada(fallo)) return;
      N.pintar(zona, [N.alerta("peligro", `No se pudieron cargar los datos. ${fallo.message}`)]);
    }
  }

  /* Ejecuta una acción sencilla y muestra el resultado. Devuelve true si se completó. */
  async function ejecutarSeguro(accion, { exito, titulo }) {
    try {
      const resultado = await accion();
      if (resultado === null) return false;
      if (exito) N.aviso("ok", exito.titulo, exito.detalle ? exito.detalle(resultado) : "");
      return true;
    } catch (fallo) {
      if (esSesionCaducada(fallo)) return false;
      N.aviso("error", titulo || "No se pudo completar la operación", fallo.message);
      return false;
    }
  }

  function cabecera(titulo, descripcion, acciones) {
    return N.cabeceraPagina({ titulo, descripcion, acciones });
  }

  function botonRefrescar(ctx) {
    return N.el("button", { class: "btn", type: "button", onclick: ctx.refrescar }, N.icono("actualizar"), "Actualizar");
  }

  function dato(seccion, leer, respaldo = "—") {
    return seccion && seccion.disponible ? leer(seccion.datos) : respaldo;
  }

  function tonoDeComprobacion(texto) {
    const minusculas = String(texto || "").toLowerCase();
    if (/ok|correct|sano|cumpl/.test(minusculas)) return "ok";
    if (/aviso|advert|pendient/.test(minusculas)) return "aviso";
    if (/error|fall|critic|no cumpl/.test(minusculas)) return "peligro";
    return "";
  }

  function opcionesEmpresa(empresas, incluirTodas) {
    const lista = empresas.map((empresa) => ({ valor: empresa.id, texto: `${empresa.nombre} (${empresa.id})` }));
    return incluirTodas ? [{ valor: "", texto: "Todas las empresas" }, ...lista] : lista;
  }

  async function empresas() {
    if (!N.estado.empresas) {
      const datos = await N.api("GET", "/api/empresas");
      N.estado.empresas = datos.empresas;
    }
    return N.estado.empresas;
  }

  function selectorEmpresa(lista, valor) {
    const plataforma = N.estado.sesion && N.estado.sesion.plataforma;
    return N.campo({
      id: "empresa",
      etiqueta: "Empresa",
      opciones: opcionesEmpresa(lista, plataforma),
      valor: valor || (plataforma ? "" : (lista[0] && lista[0].id) || ""),
      onchange: (evento) => evento.target.form.requestSubmit(),
    });
  }

  function formularioFiltros(campos, alEnviar) {
    const formulario = N.el(
      "form",
      {
        class: "filtros",
        role: "search",
        onsubmit: (evento) => {
          evento.preventDefault();
          alEnviar(Object.fromEntries(new FormData(formulario)));
        },
      },
      campos,
      N.el("button", { class: "btn", type: "submit", text: "Aplicar" })
    );
    return formulario;
  }

  function columnasGenericas(filas) {
    const claves = [...new Set(filas.flatMap((fila) => Object.keys(fila)))].slice(0, 6);
    return claves.map((clave) => ({ clave, titulo: clave }));
  }

  /* Muestra un objeto sin conocer su forma: escalares en una ficha, listas de objetos en tablas. */
  function detalleGenerico(objeto) {
    const escalares = [];
    const tablas = [];
    for (const [clave, valor] of Object.entries(objeto)) {
      if (Array.isArray(valor) && valor.length && valor.every((item) => item && typeof item === "object" && !Array.isArray(item))) {
        tablas.push([clave, valor]);
      } else {
        escalares.push([clave, valor]);
      }
    }
    const nodos = [N.ficha(escalares)];
    for (const [clave, filas] of tablas) {
      nodos.push(N.el("div", { class: "seccion-titulo", text: clave }));
      nodos.push(N.tabla({ id: `gen-${clave}`, columnas: columnasGenericas(filas), filas, buscar: filas.length > 8 }));
    }
    return nodos;
  }

  /* Pide un texto en un diálogo. Resuelve con el texto o con null si se cancela. */
  function pedirTexto({ titulo, etiqueta, ayuda = "", placeholder = "", multilinea = false, maximo = 200, boton }) {
    return new Promise((resolver) => {
      const control = multilinea
        ? N.el("textarea", { id: "pedir-texto", maxlength: String(maximo), placeholder, required: true })
        : N.el("input", { id: "pedir-texto", type: "text", maxlength: String(maximo), placeholder, required: true, autocomplete: "off", spellcheck: "false" });
      const error = N.el("div", { class: "alerta peligro", role: "alert", hidden: true });
      const enviar = () => {
        const valor = control.value.trim();
        if (!valor) {
          error.textContent = "Este campo no puede estar vacío.";
          error.hidden = false;
          return;
        }
        modal.cerrar();
        resolver(valor);
      };
      const modal = N.modal({
        titulo,
        cuerpo: [
          error,
          N.el("div", { class: "campo" }, N.el("label", { for: "pedir-texto", text: etiqueta }), control, ayuda ? N.el("span", { class: "ayuda", text: ayuda }) : null),
        ],
        alCerrar: () => resolver(null),
        pie: (cerrar) => [
          N.el("button", { class: "btn", type: "button", text: "Cancelar", onclick: cerrar }),
          N.el("button", { class: "btn btn-primario", type: "button", text: boton, onclick: enviar }),
        ],
      });
      control.addEventListener("keydown", (evento) => {
        if (evento.key === "Enter" && !multilinea) {
          evento.preventDefault();
          enviar();
        }
      });
    });
  }

  /* ---- Panel ------------------------------------------------------------------------------- */

  function construirPanel(d) {
    const estado = d.estado;
    const plugins = d.plugins;
    const modulos = d.modulos;
    const sesiones = d.sesiones;
    const alertas = d.alertas;
    const gravedad = d.gravedad;
    const tipos = d.tipos;
    const tonoEstado = tonoDeComprobacion(dato(estado, (x) => x.estado, ""));
    const kpis = N.el(
      "div",
      { class: "rejilla-kpi" },
      N.kpi({
        etiqueta: "Estado del sistema",
        valor: dato(estado, (x) => N.texto(x.estado), "Sin acceso"),
        detalle: estado.disponible ? "Último diagnóstico" : "Solo plataforma",
        tono: tonoEstado,
        icono: "mantenimiento",
      }),
      N.kpi({
        etiqueta: "Plugins habilitados",
        valor: dato(plugins, (x) => `${N.numero(x.habilitados)} / ${N.numero(x.total)}`),
        detalle: dato(plugins, (x) => `${N.numero(x.cuarentena)} en cuarentena`, plugins.motivo || ""),
        tono: dato(plugins, (x) => (x.cuarentena ? "aviso" : "ok"), ""),
        icono: "plugins",
      }),
      N.kpi({
        etiqueta: "Módulos habilitados",
        valor: dato(modulos, (x) => `${N.numero(x.habilitados)} / ${N.numero(x.total)}`),
        detalle: dato(modulos, (x) => `${N.numero(x.con_problemas)} con problemas`, modulos.motivo || ""),
        tono: dato(modulos, (x) => (x.con_problemas ? "aviso" : "ok"), ""),
        icono: "modulos",
      }),
      N.kpi({
        etiqueta: "Sesiones activas",
        valor: dato(sesiones, (x) => N.numero(x.activas)),
        detalle: sesiones.disponible ? "Vigentes ahora" : sesiones.motivo || "",
        tono: "info",
        icono: "sesiones",
      }),
      N.kpi({
        etiqueta: "Alertas de gravedad alta",
        valor: alertas.disponible ? N.numero(alertas.datos.length) : "—",
        detalle: alertas.disponible ? `En ${N.numero(d.analizados)} eventos recientes` : alertas.motivo || "",
        tono: alertas.disponible && alertas.datos.length ? "peligro" : "ok",
        icono: "alerta",
      })
    );

    const actividad = N.tabla({
      id: "panel-actividad",
      buscar: false,
      columnas: [
        { clave: "creado", titulo: "Fecha", render: (f) => N.fecha(f.creado) },
        { clave: "tipo", titulo: "Evento", render: (f) => N.el("span", { class: "mono", text: f.tipo }) },
        { clave: "gravedad", titulo: "Gravedad", render: (f) => N.gravedad(f.gravedad), ordenable: false },
        { clave: "actor", titulo: "Actor" },
      ],
      filas: actividad0(d),
      vacio: N.vacio({ icono: "eventos", titulo: "Sin actividad reciente", texto: "Todavía no hay eventos registrados." }),
    });

    const comprobaciones = estado.disponible
      ? N.tabla({
          id: "panel-comprobaciones",
          buscar: false,
          columnas: [
            { clave: "nombre", titulo: "Comprobación" },
            { clave: "estado", titulo: "Estado", render: (f) => N.estadoComprobacion(f.estado) },
            { clave: "detalle", titulo: "Detalle", envolver: true },
          ],
          filas: estado.datos.comprobaciones || [],
        })
      : N.seccionNoDisponible(estado);

    const alertasTabla = alertas.disponible
      ? N.tabla({
          id: "panel-alertas",
          buscar: false,
          columnas: [
            { clave: "creado", titulo: "Fecha", render: (f) => N.fecha(f.creado) },
            { clave: "tipo", titulo: "Evento", render: (f) => N.el("span", { class: "mono", text: f.tipo }) },
            { clave: "actor", titulo: "Actor" },
          ],
          filas: alertas.datos,
          vacio: N.vacio({ icono: "ok", titulo: "Sin alertas", texto: "No hay eventos de gravedad alta recientes." }),
        })
      : N.seccionNoDisponible(alertas);

    const dona = gravedad.disponible
      ? N.dona(
          [
            { etiqueta: "Alta", valor: gravedad.datos.alta || 0, tono: "alta" },
            { etiqueta: "Media", valor: gravedad.datos.media || 0, tono: "media" },
            { etiqueta: "Baja", valor: gravedad.datos.baja || 0, tono: "baja" },
          ],
          { total: d.analizados, etiqueta: "eventos" }
        )
      : N.seccionNoDisponible(gravedad);

    const barras = tipos.disponible && tipos.datos.length
      ? N.barras(tipos.datos.map((item) => ({ etiqueta: item.tipo, valor: item.ocurrencias })))
      : N.vacio({ titulo: "Sin datos", texto: "No hay eventos para resumir." });

    return [
      kpis,
      N.el(
        "div",
        { class: "rejilla principal" },
        N.el(
          "div",
          { class: "columna" },
          N.panel({ titulo: "Actividad reciente", sub: "Últimos eventos registrados", cuerpo: actividad, sinRelleno: true }),
          N.panel({ titulo: "Estado del sistema", sub: "Comprobaciones del diagnóstico", cuerpo: comprobaciones, sinRelleno: estado.disponible })
        ),
        N.el(
          "div",
          { class: "columna" },
          N.panel({ titulo: "Alertas recientes", sub: "Gravedad alta", cuerpo: alertasTabla, sinRelleno: true }),
          N.panel({ titulo: "Eventos por gravedad", cuerpo: dona }),
          N.panel({ titulo: "Eventos más frecuentes", sub: "En el análisis reciente", cuerpo: barras })
        )
      ),
    ];
  }

  function actividad0(d) {
    return d.actividad.disponible ? d.actividad.datos : [];
  }

  registrar("panel", {
    titulo: "Panel",
    icono: "panel",
    descripcion: "Estado de la plataforma, plugins, módulos, sesiones y actividad reciente.",
    render(main, ctx) {
      const zona = N.el("div", { class: "columna" });
      N.pintar(main, [cabecera("Panel", "Resumen del estado de la plataforma y de la actividad reciente.", botonRefrescar(ctx)), zona]);
      cargarEn(zona, () => N.api("GET", "/api/panel"), construirPanel);
    },
  });

  /* ---- Auditoría --------------------------------------------------------------------------- */

  function detalleEvento(fila) {
    const carga = fila.carga && typeof fila.carga === "object" ? Object.entries(fila.carga) : [];
    return [
      N.ficha([
        ["Fecha", N.fecha(fila.creado)],
        ["Evento", N.el("span", { class: "mono", text: fila.tipo })],
        ["Categoría", fila.categoria],
        ["Gravedad", N.gravedad(fila.gravedad)],
        ["Empresa", fila.empresa],
        ["Actor", fila.actor],
        ["Identificador", String(fila.id)],
      ]),
      N.el("div", { class: "seccion-titulo", text: "Datos del evento" }),
      carga.length ? N.ficha(carga) : N.vacio({ titulo: "Sin datos adicionales", texto: "Este evento no lleva datos." }),
    ];
  }

  function vistaEventos(ctx, datos, zonaDetalle) {
    const estado = N.estadoTabla("auditoria-eventos");
    const seleccion = N.estado.seleccion || (N.estado.seleccion = {});
    let tabla = null;
    const filas = datos.eventos;
    const mostrarDetalle = (fila) => {
      seleccion.auditoria = fila ? fila.id : null;
      N.pintar(zonaDetalle, fila ? detalleEvento(fila) : [N.vacio({ icono: "eventos", titulo: "Seleccione un evento", texto: "El detalle aparece aquí." })]);
      if (tabla) tabla.refrescarFilas();
    };
    const q = ctx.query;
    const formulario = formularioFiltros(
      [
        N.campo({ id: "categoria", etiqueta: "Categoría", opciones: [{ valor: "", texto: "Todas" }, { valor: "operativo", texto: "Operativo" }, { valor: "seguridad", texto: "Seguridad" }], valor: q.categoria || "", onchange: (e) => e.target.form.requestSubmit() }),
        N.campo({ id: "gravedad", etiqueta: "Gravedad", opciones: [{ valor: "", texto: "Todas" }, { valor: "alta", texto: "Alta" }, { valor: "media", texto: "Media" }, { valor: "baja", texto: "Baja" }], valor: q.gravedad || "", onchange: (e) => e.target.form.requestSubmit() }),
        N.campo({ id: "tipo", etiqueta: "Tipo contiene", valor: q.tipo || "", placeholder: "p. ej. plugin", autocomplete: "off", ancho: true }),
        N.campo({ id: "limite", etiqueta: "Mostrar", opciones: [{ valor: "50", texto: "50" }, { valor: "200", texto: "200" }, { valor: "500", texto: "500" }], valor: q.limite || "200", onchange: (e) => e.target.form.requestSubmit() }),
      ],
      (valores) => N.ir("auditoria", { tab: "eventos", categoria: valores.categoria, gravedad: valores.gravedad, tipo: (valores.tipo || "").trim(), limite: valores.limite })
    );
    tabla = N.tabla({
      id: "auditoria-eventos",
      columnas: [
        { clave: "creado", titulo: "Fecha", render: (f) => N.fecha(f.creado) },
        { clave: "tipo", titulo: "Evento", render: (f) => N.el("span", { class: "mono", text: f.tipo }) },
        { clave: "categoria", titulo: "Categoría" },
        { clave: "gravedad", titulo: "Gravedad", render: (f) => N.gravedad(f.gravedad) },
        { clave: "empresa", titulo: "Empresa" },
        { clave: "actor", titulo: "Actor" },
      ],
      filas,
      vacio: N.vacio({ icono: "eventos", titulo: "Sin eventos", texto: "Ningún evento coincide con los filtros." }),
      seleccion: {
        activa: (fila) => fila.id === seleccion.auditoria,
        alElegir: mostrarDetalle,
      },
      placeholder: "Buscar en los eventos mostrados…",
    });
    void estado;
    const seleccionado = filas.find((fila) => fila.id === seleccion.auditoria);
    N.pintar(zonaDetalle, seleccionado ? detalleEvento(seleccionado) : [N.vacio({ icono: "eventos", titulo: "Seleccione un evento", texto: "El detalle aparece aquí." })]);
    return [
      N.el("div", { class: "panel-cuerpo" }, formulario),
      N.el(
        "p",
        { class: "muted pie-nota" },
        `Mostrando hasta ${N.numero(filas.length)} eventos de ${N.numero(datos.coincidencias)} coincidencias. Se analizan los ${N.numero(datos.analizados)} más recientes.`
      ),
      N.el("div", { class: "rejilla principal" }, N.panel({ titulo: "Registro", sinRelleno: true, cuerpo: tabla }), N.panel({ titulo: "Detalle", cuerpo: zonaDetalle })),
    ];
  }

  function vistaEvaluaciones(ctx, datos, zonaDetalle) {
    const seleccion = N.estado.seleccion || (N.estado.seleccion = {});
    let tabla = null;
    const mostrar = async (fila) => {
      seleccion.evaluacion = fila.id;
      if (tabla) tabla.refrescarFilas();
      await cargarEn(zonaDetalle, () => N.api("GET", "/api/auditoria/evaluacion", { query: { empresa: fila.empresa, id: fila.id } }), (d) => [
        N.el("div", { class: "seccion-titulo", text: "Evaluación" }),
        ...detalleGenerico(d.evaluacion),
      ]);
    };
    tabla = N.tabla({
      id: "auditoria-evaluaciones",
      columnas: [
        { clave: "inicio", titulo: "Inicio", render: (f) => N.fecha(f.inicio) },
        { clave: "empresa", titulo: "Empresa" },
        { clave: "usuario", titulo: "Usuario" },
        { clave: "perfil", titulo: "Perfil" },
        { clave: "riesgo", titulo: "Riesgo", render: (f) => N.gravedad(f.riesgo === "critico" ? "alta" : f.riesgo === "alto" ? "alta" : f.riesgo === "medio" ? "media" : "baja") },
        { clave: "cumple", titulo: "Cumple" },
        { clave: "no_cumple", titulo: "No cumple" },
      ],
      filas: datos.evaluaciones,
      vacio: N.vacio({ icono: "auditoria", titulo: "Sin evaluaciones", texto: "Todavía no se ha registrado ninguna evaluación." }),
      seleccion: { activa: (fila) => fila.id === seleccion.evaluacion, alElegir: mostrar },
    });
    N.pintar(zonaDetalle, [N.vacio({ icono: "auditoria", titulo: "Seleccione una evaluación", texto: "Verá aquí sus resultados." })]);
    return [
      N.el("div", { class: "rejilla principal" }, N.panel({ titulo: "Evaluaciones", sub: "Resultados de cumplimiento", sinRelleno: true, cuerpo: tabla }), N.panel({ titulo: "Resultados", cuerpo: zonaDetalle })),
    ];
  }

  registrar("auditoria", {
    titulo: "Auditoría",
    icono: "auditoria",
    descripcion: "Registro de eventos y evaluaciones de cumplimiento. Solo lectura.",
    render(main, ctx) {
      const pestana = ctx.query.tab === "evaluaciones" ? "evaluaciones" : "eventos";
      const zona = N.el("div", { class: "columna" });
      const zonaContenido = N.el("div", { class: "columna" });
      const zonaDetalle = N.el("div", { class: "columna" });
      N.pintar(main, [
        cabecera("Auditoría", "Revise los eventos registrados y las evaluaciones de cumplimiento. Esta sección no modifica nada.", botonRefrescar(ctx)),
        N.pestanas(
          [
            { id: "eventos", titulo: "Registro de eventos" },
            { id: "evaluaciones", titulo: "Evaluaciones" },
          ],
          pestana,
          (id) => N.ir("auditoria", { tab: id })
        ),
        zona,
      ]);
      N.pintar(zona, [zonaContenido]);
      if (pestana === "eventos") {
        cargarEn(
          zonaContenido,
          async () => {
            const q = ctx.query;
            const datos = await N.api("GET", "/api/auditoria/eventos", {
              query: { categoria: q.categoria, gravedad: q.gravedad, tipo: q.tipo, empresa: q.empresa, limite: q.limite || "200" },
            });
            return datos;
          },
          (datos) => vistaEventos(ctx, datos, zonaDetalle)
        );
      } else {
        cargarEn(zonaContenido, () => N.api("GET", "/api/auditoria/evaluaciones"), (datos) => vistaEvaluaciones(ctx, datos, zonaDetalle));
      }
    },
  });

  /* ---- Usuarios ---------------------------------------------------------------------------- */

  function detalleCuenta(d) {
    const cuenta = d.cuenta;
    return [
      N.ficha([
        ["Usuario", cuenta.usuario],
        ["Estado", N.estadoCuenta(cuenta.estado)],
        ["Empresa", cuenta.empresa],
        ["Sesiones activas", N.numero(d.sesiones_activas)],
      ]),
      N.el("div", { class: "seccion-titulo", text: "Roles" }),
      N.chips(cuenta.roles),
      N.el("div", { class: "seccion-titulo", text: `Permisos efectivos (${N.numero(d.permisos.length)})` }),
      d.permisos.length
        ? N.el("div", { class: "chips" }, d.permisos.slice(0, 200).map((permiso) => N.el("span", { class: "chip", text: permiso })))
        : N.vacio({ titulo: "Sin permisos", texto: "La cuenta no tiene permisos efectivos." }),
    ];
  }

  registrar("usuarios", {
    titulo: "Usuarios",
    icono: "usuarios",
    descripcion: "Cuentas, roles y permisos efectivos. Solo lectura: las altas y los cambios se hacen desde la terminal.",
    render(main, ctx) {
      const zonaLista = N.el("div", { class: "columna" });
      const zonaDetalle = N.el("div", { class: "columna" });
      const seleccion = N.estado.seleccion || (N.estado.seleccion = {});
      N.pintar(main, [
        cabecera("Usuarios y permisos", "Cuentas de la plataforma y de cada empresa, con sus roles y permisos efectivos.", botonRefrescar(ctx)),
        zonaLista,
      ]);
      const empresaElegida = ctx.query.empresa || "";
      cargarEn(
        zonaLista,
        async () => {
          const [cuentas, lista] = await Promise.all([
            N.api("GET", "/api/usuarios", { query: { empresa: empresaElegida } }),
            empresas(),
          ]);
          return { cuentas, lista };
        },
        ({ cuentas, lista }) => {
          let tabla = null;
          const elegir = (fila) => {
            seleccion.usuario = fila.usuario;
            if (tabla) tabla.refrescarFilas();
            cargarEn(zonaDetalle, () => N.api("GET", "/api/usuarios/detalle", { query: { usuario: fila.usuario } }), (d) => detalleCuenta(d));
          };
          tabla = N.tabla({
            id: "usuarios-cuentas",
            columnas: [
              { clave: "usuario", titulo: "Usuario" },
              { clave: "estado", titulo: "Estado", render: (f) => N.estadoCuenta(f.estado) },
              { clave: "roles", titulo: "Roles", texto: (f) => f.roles.join(" "), render: (f) => N.chips(f.roles) },
              { clave: "empresa", titulo: "Empresa" },
            ],
            filas: cuentas.cuentas,
            vacio: N.vacio({ icono: "usuarios", titulo: "Sin cuentas", texto: "No hay cuentas en el ámbito elegido." }),
            seleccion: { activa: (fila) => fila.usuario === seleccion.usuario, alElegir: elegir },
          });
          const filtro = formularioFiltros([selectorEmpresa(lista, empresaElegida)], (valores) => N.ir("usuarios", { empresa: valores.empresa }));
          N.pintar(zonaDetalle, [N.vacio({ icono: "usuarios", titulo: "Seleccione una cuenta", texto: "Verá sus roles, permisos y sesiones." })]);
          const detalleInicial = cuentas.cuentas.find((fila) => fila.usuario === seleccion.usuario);
          if (detalleInicial) elegir(detalleInicial);
          N.pintar(zonaLista, [
            N.el("div", { class: "panel-cuerpo" }, filtro),
            N.el("div", { class: "rejilla principal" }, N.panel({ titulo: "Cuentas", sinRelleno: true, cuerpo: tabla }), N.panel({ titulo: "Detalle de la cuenta", cuerpo: zonaDetalle })),
          ]);
        }
      );
    },
  });

  /* ---- Sesiones ---------------------------------------------------------------------------- */

  function claveSesion(fila) {
    return `${fila.usuario}|${fila.creada}`;
  }

  registrar("sesiones", {
    titulo: "Sesiones",
    icono: "sesiones",
    descripcion: "Sesiones vigentes. Vista de solo lectura: la revocación no está disponible en la interfaz.",
    render(main, ctx) {
      const zona = N.el("div", { class: "columna" });
      const zonaDetalle = N.el("div", { class: "columna" });
      const seleccion = N.estado.seleccion || (N.estado.seleccion = {});
      N.pintar(main, [cabecera("Sesiones", "Sesiones vigentes de la plataforma y de cada empresa. La revocación todavía no está disponible en esta interfaz.", botonRefrescar(ctx)), zona]);
      const empresaElegida = ctx.query.empresa || "";
      cargarEn(
        zona,
        async () => ({ sesiones: await N.api("GET", "/api/sesiones", { query: { empresa: empresaElegida } }), lista: await empresas() }),
        ({ sesiones, lista }) => {
          let tabla = null;
          const elegir = (fila) => {
            seleccion.sesion = claveSesion(fila);
            if (tabla) tabla.refrescarFilas();
            N.pintar(zonaDetalle, [
              N.ficha([
                ["Usuario", fila.usuario],
                ["Empresa", fila.empresa],
                ["Creada", N.fecha(fila.creada)],
                ["Última actividad", N.fecha(fila.ultima_actividad)],
                ["Expira", N.fecha(fila.expira)],
                ["Reautenticada", fila.reautenticada ? N.badge("Sí", "azul") : N.badge("No", "neutro")],
              ]),
              N.el("p", { class: "ayuda muted", text: "Las sesiones caducan por inactividad a los 15 minutos y, como máximo, a las 8 horas." }),
            ]);
          };
          tabla = N.tabla({
            id: "sesiones-lista",
            columnas: [
              { clave: "usuario", titulo: "Usuario" },
              { clave: "empresa", titulo: "Empresa" },
              { clave: "creada", titulo: "Creada", render: (f) => N.fecha(f.creada) },
              { clave: "ultima_actividad", titulo: "Última actividad", render: (f) => N.fecha(f.ultima_actividad) },
              { clave: "expira", titulo: "Expira", render: (f) => N.fecha(f.expira) },
              { clave: "reautenticada", titulo: "Reautenticada", render: (f) => (f.reautenticada ? N.badge("Sí", "azul") : N.badge("No", "neutro")) },
            ],
            filas: sesiones.sesiones,
            vacio: N.vacio({ icono: "sesiones", titulo: "Sin sesiones activas", texto: "No hay sesiones vigentes en el ámbito elegido." }),
            seleccion: { activa: (fila) => claveSesion(fila) === seleccion.sesion, alElegir: elegir },
          });
          const filtro = formularioFiltros([selectorEmpresa(lista, empresaElegida)], (valores) => N.ir("sesiones", { empresa: valores.empresa }));
          N.pintar(zonaDetalle, [N.vacio({ icono: "sesiones", titulo: "Seleccione una sesión", texto: "Verá aquí su estado." })]);
          N.pintar(zona, [
            N.el("div", { class: "panel-cuerpo" }, filtro),
            N.el("div", { class: "rejilla principal" }, N.panel({ titulo: "Sesiones vigentes", sub: `${N.numero(sesiones.sesiones.length)} en la lista`, sinRelleno: true, cuerpo: tabla }), N.panel({ titulo: "Estado de la sesión", cuerpo: zonaDetalle })),
          ]);
        }
      );
    },
  });

  /* ---- Plugins ----------------------------------------------------------------------------- */

  function abrirCuarentena(plugin, alHecho) {
    const motivo = N.el("textarea", { id: "motivo", maxlength: "200", required: true, placeholder: "Por qué se pone el plugin en cuarentena" });
    const error = N.el("div", { class: "alerta peligro", role: "alert", hidden: true });
    let modal = null;
    const enviar = async () => {
      const texto = motivo.value.trim();
      if (!texto) {
        error.textContent = "Escriba un motivo.";
        error.hidden = false;
        return;
      }
      try {
        const resultado = await N.api("POST", "/api/acciones/plugins/cuarentena", { cuerpo: { plugin_id: plugin.id, motivo: texto } });
        modal.cerrar();
        N.aviso("ok", "Plugin en cuarentena", `${plugin.id}. Deshabilitados: ${resultado.deshabilitados.length}`);
        alHecho();
      } catch (fallo) {
        if (esSesionCaducada(fallo)) return;
        error.textContent = fallo.message;
        error.hidden = false;
      }
    };
    modal = N.modal({
      titulo: `Poner en cuarentena: ${plugin.id}`,
      cuerpo: [
        N.el("p", { class: "muted", text: "La cuarentena deshabilita el plugin y los que dependen de él. No ejecuta ni borra nada." }),
        error,
        N.el("div", { class: "campo" }, N.el("label", { for: "motivo", text: "Motivo" }), motivo, N.el("span", { class: "ayuda", text: "De 1 a 200 caracteres." })),
      ],
      pie: (cerrar) => [
        N.el("button", { class: "btn", type: "button", text: "Cancelar", onclick: cerrar }),
        N.el("button", { class: "btn btn-peligro", type: "button", text: "Poner en cuarentena", onclick: enviar }),
      ],
    });
  }

  registrar("plugins", {
    titulo: "Plugins",
    icono: "plugins",
    descripcion: "Estado, versiones y cuarentena de los plugins instalados.",
    render(main, ctx) {
      const zona = N.el("div", { class: "columna" });
      N.pintar(main, [
        cabecera(
          "Plugins",
          "Estado, versiones y cuarentena. Los cambios de versión y la liberación de la cuarentena son operaciones críticas. Instalar y habilitar se hace desde la terminal.",
          botonRefrescar(ctx)
        ),
        zona,
      ]);
      cargarEn(zona, () => N.api("GET", "/api/plugins"), (datos) => vistaPlugins(ctx, datos));
    },
  });

  function vistaPlugins(ctx, datos) {
    const seleccion = N.estado.seleccion || (N.estado.seleccion = {});
    const zonaDetalle = N.el("div", { class: "columna" });
    let tabla = null;
    const acciones = (plugin) => {
      const refrescar = () => ctx.refrescar();
      return N.el(
        "div",
        { class: "columna" },
        N.el("button", { class: "btn", type: "button", onclick: () => abrirCuarentena(plugin, refrescar), text: "Poner en cuarentena" }),
        N.el("button", {
          class: "btn btn-peligro",
          type: "button",
          disabled: !plugin.cuarentena,
          text: "Liberar cuarentena (crítica)",
          onclick: async () => {
            await ejecutarSeguro(
              () => N.accionCritica((confirmado) => N.api("POST", "/api/acciones/plugins/liberar", { cuerpo: { plugin_id: plugin.id, confirmado } }), {
                titulo: `Liberar la cuarentena de ${plugin.id}`,
                texto: "Liberar la cuarentena no habilita el plugin. Habilitarlo es una operación aparte.",
                etiqueta: "Liberar cuarentena",
              }),
              { exito: { titulo: "Cuarentena liberada", detalle: () => plugin.id }, titulo: "No se liberó la cuarentena" }
            );
            refrescar();
          },
        }),
        N.el("button", {
          class: "btn btn-peligro",
          type: "button",
          text: "Actualizar desde carpeta (crítica)",
          disabled: plugin.habilitado,
          onclick: async () => {
            const carpeta = await pedirTexto({
              titulo: `Actualizar ${plugin.id}`,
              etiqueta: "Carpeta del paquete firmado",
              ayuda: "La versión nueva debe ser mayor, del mismo editor y el plugin debe estar deshabilitado.",
              placeholder: "Ruta completa de la carpeta",
              maximo: 500,
              boton: "Continuar",
            });
            if (!carpeta) return;
            await ejecutarSeguro(
              () => N.accionCritica((confirmado) => N.api("POST", "/api/acciones/plugins/actualizar", { cuerpo: { carpeta, confirmado } }), {
                titulo: `Actualizar ${plugin.id}`,
                texto: "La versión anterior queda conservada para revertir. El plugin queda deshabilitado.",
                etiqueta: "Actualizar",
              }),
              { exito: { titulo: "Plugin actualizado", detalle: (r) => `${r.plugin} · versión ${r.version}` }, titulo: "No se actualizó el plugin" }
            );
            refrescar();
          },
        }),
        N.el("button", {
          class: "btn btn-peligro",
          type: "button",
          disabled: !plugin.version_anterior,
          text: "Revertir a la versión anterior (crítica)",
          onclick: async () => {
            await ejecutarSeguro(
              () => N.accionCritica((confirmado) => N.api("POST", "/api/acciones/plugins/revertir", { cuerpo: { plugin_id: plugin.id, confirmado } }), {
                titulo: `Revertir ${plugin.id}`,
                texto: `Vuelve a la versión ${plugin.version_anterior}. Revertir otra vez devuelve la versión actual.`,
                etiqueta: "Revertir",
              }),
              { exito: { titulo: "Versión revertida", detalle: (r) => `${r.plugin} · versión ${r.version}` }, titulo: "No se revirtió el plugin" }
            );
            refrescar();
          },
        })
      );
    };
    const mostrarDetalle = (plugin) => {
      seleccion.plugin = plugin.id;
      if (tabla) tabla.refrescarFilas();
      N.pintar(zonaDetalle, [
        N.ficha([
          ["Plugin", plugin.id],
          ["Versión", plugin.version],
          ["Estado", N.estadoPlugin(plugin)],
          ["Versión anterior", plugin.version_anterior],
          ["Editor", plugin.editor],
          ["Confianza", plugin.confianza],
          ["Revisión aprobada", plugin.revision_aprobada],
          ["Integridad (SHA-256)", N.el("span", { class: "mono", text: plugin.integridad })],
        ]),
        N.el("div", { class: "seccion-titulo", text: "Dependencias" }),
        N.chips(plugin.dependencias),
        N.el("div", { class: "seccion-titulo", text: "Operaciones" }),
        acciones(plugin),
      ]);
    };
    tabla = N.tabla({
      id: "plugins-lista",
      columnas: [
        { clave: "id", titulo: "Plugin", render: (f) => N.el("span", { class: "mono", text: f.id }) },
        { clave: "version", titulo: "Versión" },
        { clave: "estado", titulo: "Estado", valor: (f) => (f.cuarentena ? 2 : f.habilitado ? 1 : 0), render: (f) => N.estadoPlugin(f) },
        { clave: "editor", titulo: "Editor", envolver: false },
        { clave: "confianza", titulo: "Confianza" },
        { clave: "version_anterior", titulo: "Anterior" },
      ],
      filas: datos.plugins,
      vacio: N.vacio({ icono: "plugins", titulo: "Sin plugins", texto: "No hay plugins instalados." }),
      seleccion: { activa: (fila) => fila.id === seleccion.plugin, alElegir: mostrarDetalle },
    });
    const resumen = datos.resumen;
    const lista = [
      N.el(
        "div",
        { class: "rejilla-kpi" },
        N.kpi({ etiqueta: "Instalados", valor: N.numero(resumen.total), icono: "plugins" }),
        N.kpi({ etiqueta: "Habilitados", valor: N.numero(resumen.habilitados), tono: "ok", icono: "ok" }),
        N.kpi({ etiqueta: "En cuarentena", valor: N.numero(resumen.cuarentena), tono: resumen.cuarentena ? "peligro" : "", icono: "seguridad" })
      ),
      N.el("div", { class: "rejilla principal" }, N.panel({ titulo: "Catálogo", sinRelleno: true, cuerpo: tabla }), N.panel({ titulo: "Detalle y operaciones", cuerpo: zonaDetalle })),
    ];
    const elegido = datos.plugins.find((plugin) => plugin.id === seleccion.plugin);
    N.pintar(zonaDetalle, [N.vacio({ icono: "plugins", titulo: "Seleccione un plugin", texto: "Verá sus datos y las operaciones disponibles." })]);
    if (elegido) mostrarDetalle(elegido);
    return lista;
  }

  /* ---- Módulos ----------------------------------------------------------------------------- */

  registrar("modulos", {
    titulo: "Módulos",
    icono: "modulos",
    descripcion: "Módulos instalados, dependencias y problemas. Habilitar o deshabilitar es una operación crítica.",
    render(main, ctx) {
      const zona = N.el("div", { class: "columna" });
      N.pintar(main, [cabecera("Módulos", "Módulos instalados, con sus dependencias, permisos y problemas detectados.", botonRefrescar(ctx)), zona]);
      cargarEn(zona, () => N.api("GET", "/api/modulos"), (datos) => vistaModulos(ctx, datos));
    },
  });

  function vistaModulos(ctx, datos) {
    const seleccion = N.estado.seleccion || (N.estado.seleccion = {});
    const zonaDetalle = N.el("div", { class: "columna" });
    let tabla = null;
    const cambiar = async (modulo, habilitar) => {
      const operacion = habilitar ? "habilitar" : "deshabilitar";
      await ejecutarSeguro(
        () => N.accionCritica((confirmado) => N.api("POST", `/api/acciones/modulos/${operacion}`, { cuerpo: { modulo_id: modulo.id, confirmado } }), {
          titulo: `${habilitar ? "Habilitar" : "Deshabilitar"} ${modulo.id}`,
          texto: habilitar ? "Habilitar un módulo amplía lo que puede hacer la plataforma." : "Deshabilitar un módulo lo retira de la plataforma.",
          etiqueta: habilitar ? "Habilitar" : "Deshabilitar",
        }),
        { exito: { titulo: habilitar ? "Módulo habilitado" : "Módulo deshabilitado", detalle: () => modulo.id }, titulo: "No se cambió el módulo" }
      );
      ctx.refrescar();
    };
    const mostrarDetalle = (modulo) => {
      seleccion.modulo = modulo.id;
      if (tabla) tabla.refrescarFilas();
      N.pintar(zonaDetalle, [
        N.ficha([
          ["Módulo", modulo.id],
          ["Nombre", modulo.nombre],
          ["Versión", modulo.version],
          ["Estado", N.estadoModulo(modulo)],
          ["Descripción", modulo.descripcion],
        ]),
        N.el("div", { class: "seccion-titulo", text: "Requiere" }),
        N.chips(modulo.requiere),
        N.el("div", { class: "seccion-titulo", text: "Permisos" }),
        N.chips(modulo.permisos),
        N.el("div", { class: "seccion-titulo", text: "Problemas" }),
        modulo.problemas.length ? N.el("ul", { class: "lista-simple" }, modulo.problemas.map((p) => N.el("li", null, N.icono("alerta"), N.el("span", { text: p })))) : N.el("span", { class: "muted", text: "Ninguno" }),
        N.el("div", { class: "seccion-titulo", text: "Operaciones" }),
        N.el(
          "div",
          { class: "columna" },
          modulo.habilitado
            ? N.el("button", { class: "btn btn-peligro", type: "button", text: "Deshabilitar (crítica)", onclick: () => cambiar(modulo, false) })
            : N.el("button", { class: "btn btn-peligro", type: "button", text: "Habilitar (crítica)", onclick: () => cambiar(modulo, true) })
        ),
      ]);
    };
    tabla = N.tabla({
      id: "modulos-lista",
      columnas: [
        { clave: "id", titulo: "Módulo", render: (f) => N.el("span", { class: "mono", text: f.id }) },
        { clave: "version", titulo: "Versión" },
        { clave: "estado", titulo: "Estado", valor: (f) => (f.habilitado ? 1 : 0), render: (f) => N.estadoModulo(f) },
        { clave: "requiere", titulo: "Requiere", texto: (f) => f.requiere.length, render: (f) => N.numero(f.requiere.length) },
        { clave: "permisos", titulo: "Permisos", texto: (f) => f.permisos.length, render: (f) => N.numero(f.permisos.length) },
      ],
      filas: datos.modulos,
      vacio: N.vacio({ icono: "modulos", titulo: "Sin módulos", texto: "No hay módulos en la carpeta modules/." }),
      seleccion: { activa: (fila) => fila.id === seleccion.modulo, alElegir: mostrarDetalle },
    });
    const resumen = datos.resumen;
    const lista = [
      N.el(
        "div",
        { class: "rejilla-kpi" },
        N.kpi({ etiqueta: "Instalados", valor: N.numero(resumen.total), icono: "modulos" }),
        N.kpi({ etiqueta: "Habilitados", valor: N.numero(resumen.habilitados), tono: "ok", icono: "ok" }),
        N.kpi({ etiqueta: "Con problemas", valor: N.numero(resumen.con_problemas), tono: resumen.con_problemas ? "aviso" : "", icono: "alerta" })
      ),
      N.el("div", { class: "rejilla principal" }, N.panel({ titulo: "Catálogo", sinRelleno: true, cuerpo: tabla }), N.panel({ titulo: "Detalle y operaciones", cuerpo: zonaDetalle })),
    ];
    const elegido = datos.modulos.find((modulo) => modulo.id === seleccion.modulo);
    N.pintar(zonaDetalle, [N.vacio({ icono: "modulos", titulo: "Seleccione un módulo", texto: "Verá sus dependencias y problemas." })]);
    if (elegido) mostrarDetalle(elegido);
    return lista;
  }

  /* ---- Reportes ---------------------------------------------------------------------------- */

  function abrirGenerarInforme(lista, alHecho) {
    const formatos = ["json", "csv", "html", "txt"];
    const selectEmpresa = N.campo({
      id: "empresa",
      etiqueta: "Empresa",
      opciones: opcionesEmpresa(lista, false),
      valor: lista[0] ? lista[0].id : "",
    });
    const selectEvaluacion = N.campo({ id: "evaluacion", etiqueta: "Evaluación", opciones: [{ valor: "", texto: "Cargando…" }] });
    const selectFormato = N.campo({ id: "formato", etiqueta: "Formato", opciones: formatos.map((f) => ({ valor: f, texto: f.toUpperCase() })), valor: "html" });
    const error = N.el("div", { class: "alerta peligro", role: "alert", hidden: true });
    const empresaSelect = selectEmpresa.querySelector("select");
    const evaluacionSelect = selectEvaluacion.querySelector("select");
    let modal = null;
    const cargarEvaluaciones = async () => {
      evaluacionSelect.replaceChildren(N.el("option", { value: "", text: "Cargando…" }));
      try {
        const datos = await N.api("GET", "/api/auditoria/evaluaciones", { query: { empresa: empresaSelect.value } });
        const opciones = datos.evaluaciones.map((e) => N.el("option", { value: e.id, text: `${N.fecha(e.inicio)} · ${e.usuario} · ${e.perfil}` }));
        evaluacionSelect.replaceChildren(...(opciones.length ? opciones : [N.el("option", { value: "", text: "Sin evaluaciones" })]));
      } catch (fallo) {
        if (esSesionCaducada(fallo)) return;
        error.textContent = fallo.message;
        error.hidden = false;
      }
    };
    empresaSelect.addEventListener("change", cargarEvaluaciones);
    const enviar = async () => {
      if (!evaluacionSelect.value) {
        error.textContent = "Elija una evaluación.";
        error.hidden = false;
        return;
      }
      try {
        const datos = await N.api("POST", "/api/acciones/informes/exportar", {
          cuerpo: { empresa: empresaSelect.value, evaluacion: evaluacionSelect.value, formato: selectFormato.querySelector("select").value },
        });
        modal.cerrar();
        N.aviso("ok", "Informe generado", `Formato ${datos.informe.formato || ""}`.trim());
        alHecho();
      } catch (fallo) {
        if (esSesionCaducada(fallo)) return;
        error.textContent = fallo.message;
        error.hidden = false;
      }
    };
    modal = N.modal({
      titulo: "Generar informe",
      cuerpo: [
        N.el("p", { class: "muted", text: "El informe se genera a partir de una evaluación ya registrada." }),
        error,
        selectEmpresa,
        selectEvaluacion,
        selectFormato,
      ],
      pie: (cerrar) => [
        N.el("button", { class: "btn", type: "button", text: "Cancelar", onclick: cerrar }),
        N.el("button", { class: "btn btn-primario", type: "button", text: "Generar", onclick: enviar }),
      ],
    });
    cargarEvaluaciones();
  }

  registrar("reportes", {
    titulo: "Reportes",
    icono: "reportes",
    descripcion: "Historial de informes y su verificación. Los informes se generan a partir de evaluaciones existentes.",
    render(main, ctx) {
      const zona = N.el("div", { class: "columna" });
      const zonaDetalle = N.el("div", { class: "columna" });
      const seleccion = N.estado.seleccion || (N.estado.seleccion = {});
      const empresaElegida = ctx.query.empresa || "";
      N.pintar(main, [
        cabecera("Reportes", "Historial de informes exportados. Puede verificar su integridad y generar nuevos informes.", N.el("div", { class: "acciones" }, botonRefrescar(ctx))),
        zona,
      ]);
      cargarEn(
        zona,
        async () => ({ informes: await N.api("GET", "/api/informes", { query: { empresa: empresaElegida } }), lista: await empresas() }),
        ({ informes, lista }) => {
          let tabla = null;
          const verificarBoton = N.el("button", {
            class: "btn",
            type: "button",
            text: "Verificar informes",
            onclick: async () => {
              const empresa = empresaElegida || (lista[0] && lista[0].id) || "";
              try {
                const resultado = await N.api("POST", "/api/acciones/informes/verificar", { cuerpo: { empresa } });
                N.pintar(zonaDetalle, [
                  N.el("div", { class: "seccion-titulo", text: "Resultado de la verificación" }),
                  ...detalleGenerico({ verificacion: resultado.verificacion }),
                ]);
                N.aviso("ok", "Verificación completada", N.numero(resultado.verificacion.length) + " registros revisados");
              } catch (fallo) {
                if (!esSesionCaducada(fallo)) N.aviso("error", "No se pudo verificar", fallo.message);
              }
            },
          });
          const generarBoton = N.el("button", { class: "btn btn-primario", type: "button", text: "Generar informe", onclick: () => abrirGenerarInforme(lista, () => ctx.refrescar()) });
          const acciones = N.el("div", { class: "acciones" }, verificarBoton, generarBoton);
          tabla = N.tabla({
            id: "informes-lista",
            columnas: [
              { clave: "creado", titulo: "Creado", render: (f) => N.fecha(f.creado) },
              { clave: "empresa", titulo: "Empresa" },
              { clave: "evaluacion", titulo: "Evaluación", render: (f) => N.el("span", { class: "mono", text: f.evaluacion }) },
              { clave: "formato", titulo: "Formato", render: (f) => N.el("span", { class: "chip", text: String(f.formato).toUpperCase() }) },
              { clave: "usuario", titulo: "Usuario" },
              { clave: "bytes", titulo: "Tamaño", render: (f) => N.texto(f.bytes ? `${N.numero(f.bytes)} B` : "—") },
            ],
            filas: informes.informes,
            vacio: N.vacio({ icono: "reportes", titulo: "Sin informes", texto: "Todavía no se ha exportado ningún informe." }),
            seleccion: {
              activa: (fila) => fila.id === seleccion.informe,
              alElegir: (fila) => {
                seleccion.informe = fila.id;
                if (tabla) tabla.refrescarFilas();
                cargarEn(zonaDetalle, async () => ({ fila, evaluacion: await N.api("GET", "/api/auditoria/evaluacion", { query: { empresa: fila.empresa, id: fila.evaluacion } }) }), ({ fila: f, evaluacion }) => [
                  N.el("div", { class: "seccion-titulo", text: "Datos del informe" }),
                  N.ficha([
                    ["Empresa", f.empresa],
                    ["Formato", String(f.formato).toUpperCase()],
                    ["Usuario", f.usuario],
                    ["Creado", N.fecha(f.creado)],
                    ["Tamaño", N.texto(f.bytes ? `${N.numero(f.bytes)} B` : "—")],
                  ]),
                  N.el("div", { class: "seccion-titulo", text: "Vista previa de la evaluación" }),
                  ...detalleGenerico(evaluacion.evaluacion),
                ]);
              },
            },
          });
          const filtro = formularioFiltros([selectorEmpresa(lista, empresaElegida)], (valores) => N.ir("reportes", { empresa: valores.empresa }));
          N.pintar(zonaDetalle, [N.vacio({ icono: "reportes", titulo: "Seleccione un informe", texto: "Verá sus datos y una vista previa de la evaluación." })]);
          N.pintar(zona, [
            N.el("div", { class: "barra-herramientas" }, filtro, acciones),
            N.el("div", { class: "rejilla principal" }, N.panel({ titulo: "Historial", sub: `${N.numero(informes.informes.length)} informes`, sinRelleno: true, cuerpo: tabla }), N.panel({ titulo: "Vista previa", cuerpo: zonaDetalle })),
          ]);
        }
      );
    },
  });

  /* ---- Eventos (catálogo) ------------------------------------------------------------------ */

  registrar("eventos", {
    titulo: "Eventos",
    icono: "eventos",
    descripcion: "Catálogo de tipos de evento, con sus claves y su número de apariciones recientes.",
    render(main, ctx) {
      const zona = N.el("div", { class: "columna" });
      N.pintar(main, [cabecera("Catálogo de eventos", "Tipos de evento que registra la plataforma, con las claves que lleva cada uno y cuántas veces aparecen en el análisis reciente.", botonRefrescar(ctx)), zona]);
      cargarEn(zona, () => N.api("GET", "/api/eventos/catalogo", { query: { empresa: ctx.query.empresa || "" } }), (datos) => {
        const tipos = datos.tipos;
        const seguridad = tipos.filter((t) => t.categoria === "seguridad").length;
        let tabla = null;
        tabla = N.tabla({
          id: "eventos-catalogo",
          columnas: [
            { clave: "tipo", titulo: "Tipo", render: (f) => N.el("span", { class: "mono", text: f.tipo }) },
            { clave: "categoria", titulo: "Categoría", render: (f) => N.badge(f.categoria, f.categoria === "seguridad" ? "aviso" : "info") },
            { clave: "obligatorias", titulo: "Claves obligatorias", texto: (f) => f.obligatorias.join(" "), render: (f) => N.chips(f.obligatorias), envolver: true },
            { clave: "opcionales", titulo: "Opcionales", texto: (f) => f.opcionales.join(" "), render: (f) => N.chips(f.opcionales), envolver: true },
            { clave: "ocurrencias", titulo: "Apariciones", render: (f) => N.numero(f.ocurrencias) },
          ],
          filas: tipos,
          vacio: N.vacio({ icono: "eventos", titulo: "Sin tipos", texto: "El catálogo está vacío." }),
        });
        N.pintar(zona, [
          N.el("div", { class: "rejilla-kpi" },
            N.kpi({ etiqueta: "Tipos definidos", valor: N.numero(tipos.length), icono: "eventos" }),
            N.kpi({ etiqueta: "De seguridad", valor: N.numero(seguridad), tono: "aviso", icono: "seguridad" }),
            N.kpi({ etiqueta: "Operativos", valor: N.numero(tipos.length - seguridad), tono: "info", icono: "configuracion" })),
          N.panel({ titulo: "Catálogo", sub: `Análisis de los ${N.numero(datos.analizados)} eventos más recientes`, sinRelleno: true, cuerpo: tabla }),
        ]);
      });
    },
  });

  /* ---- Seguridad --------------------------------------------------------------------------- */

  registrar("seguridad", {
    titulo: "Seguridad",
    icono: "seguridad",
    descripcion: "Postura de la plataforma: alertas, cuentas deshabilitadas, cuarentenas y módulos con problemas.",
    render(main, ctx) {
      const zona = N.el("div", { class: "columna" });
      N.pintar(main, [cabecera("Seguridad", "Alertas y postura de la plataforma. Cualquier problema visible aquí se puede revisar en su sección.", botonRefrescar(ctx)), zona]);
      cargarEn(zona, () => N.api("GET", "/api/seguridad", { query: { empresa: ctx.query.empresa || "" } }), (d) => {
        const cuentas = d.cuentas;
        const sesiones = d.sesiones;
        const cuarentena = d.plugins_en_cuarentena;
        const modulos = d.modulos_con_problemas;
        const nodos = [];
        if (d.instalacion_pendiente) {
          nodos.push(N.alerta("aviso", "La instalación inicial no está completa. Complétela desde la terminal antes de usar la interfaz."));
        }
        if (d.plataforma) nodos.push(N.alerta("info", d.plataforma));
        nodos.push(
          N.el(
            "div",
            { class: "rejilla-kpi" },
            N.kpi({ etiqueta: "Alertas de gravedad alta", valor: N.numero(d.alertas.length), tono: d.alertas.length ? "peligro" : "ok", icono: "alerta" }),
            N.kpi({ etiqueta: "Cuentas", valor: dato(cuentas, (x) => N.numero(x.total)), detalle: cuentas.disponible ? `${N.numero(cuentas.datos.deshabilitadas.length)} deshabilitadas` : cuentas.motivo || "", icono: "usuarios" }),
            N.kpi({ etiqueta: "Sesiones activas", valor: dato(sesiones, (x) => N.numero(x.activas)), icono: "sesiones" }),
            N.kpi({ etiqueta: "Plugins en cuarentena", valor: dato(cuarentena, (x) => N.numero(x.length)), tono: cuarentena.disponible && cuarentena.datos.length ? "peligro" : "ok", icono: "plugins" }),
            N.kpi({ etiqueta: "Módulos con problemas", valor: dato(modulos, (x) => N.numero(x.length)), tono: modulos.disponible && modulos.datos.length ? "aviso" : "ok", icono: "modulos" })
          )
        );
        const tablaAlertas = N.tabla({
          id: "seguridad-alertas",
          columnas: [
            { clave: "creado", titulo: "Fecha", render: (f) => N.fecha(f.creado) },
            { clave: "tipo", titulo: "Evento", render: (f) => N.el("span", { class: "mono", text: f.tipo }) },
            { clave: "actor", titulo: "Actor" },
            { clave: "empresa", titulo: "Empresa" },
          ],
          filas: d.alertas,
          vacio: N.vacio({ icono: "ok", titulo: "Sin alertas", texto: "No hay eventos de gravedad alta en el análisis reciente." }),
        });
        nodos.push(N.panel({ titulo: "Alertas", sub: "Eventos de gravedad alta", sinRelleno: true, cuerpo: tablaAlertas }));
        nodos.push(
          N.el(
            "div",
            { class: "rejilla" },
            N.panel({
              titulo: "Cuentas deshabilitadas",
              sinRelleno: true,
              cuerpo: cuentas.disponible
                ? N.tabla({
                    id: "seguridad-cuentas",
                    buscar: false,
                    columnas: [
                      { clave: "usuario", titulo: "Usuario" },
                      { clave: "empresa", titulo: "Empresa" },
                      { clave: "estado", titulo: "Estado", render: (f) => N.estadoCuenta(f.estado) },
                    ],
                    filas: cuentas.datos.deshabilitadas,
                    vacio: N.vacio({ icono: "ok", titulo: "Ninguna", texto: "No hay cuentas deshabilitadas." }),
                  })
                : N.seccionNoDisponible(cuentas),
            }),
            N.panel({
              titulo: "Plugins en cuarentena",
              sinRelleno: true,
              cuerpo: cuarentena.disponible
                ? N.tabla({
                    id: "seguridad-cuarentena",
                    buscar: false,
                    columnas: [
                      { clave: "id", titulo: "Plugin", render: (f) => N.el("span", { class: "mono", text: f.id }) },
                      { clave: "version", titulo: "Versión" },
                      { clave: "estado", titulo: "Estado", render: (f) => N.estadoPlugin(f) },
                    ],
                    filas: cuarentena.datos,
                    vacio: N.vacio({ icono: "ok", titulo: "Ninguno", texto: "No hay plugins en cuarentena." }),
                  })
                : N.seccionNoDisponible(cuarentena),
            })
          )
        );
        nodos.push(
          N.panel({
            titulo: "Módulos con problemas",
            sinRelleno: true,
            cuerpo: modulos.disponible
              ? N.tabla({
                  id: "seguridad-modulos",
                  buscar: false,
                  columnas: [
                    { clave: "id", titulo: "Módulo", render: (f) => N.el("span", { class: "mono", text: f.id }) },
                    { clave: "problemas", titulo: "Problemas", texto: (f) => f.problemas.join(" "), render: (f) => N.el("span", { text: f.problemas.join(" · ") }), envolver: true },
                  ],
                  filas: modulos.datos,
                  vacio: N.vacio({ icono: "ok", titulo: "Ninguno", texto: "Ningún módulo tiene problemas." }),
                })
              : N.seccionNoDisponible(modulos),
          })
        );
        return nodos;
      });
    },
  });

  /* ---- Mantenimiento ----------------------------------------------------------------------- */

  registrar("mantenimiento", {
    titulo: "Mantenimiento",
    icono: "mantenimiento",
    descripcion: "Diagnóstico del sistema y limpieza de temporales. La limpieza borra archivos y exige confirmación.",
    render(main, ctx) {
      const zona = N.el("div", { class: "columna" });
      const descargar = N.el("button", {
        class: "btn",
        type: "button",
        text: "Exportar diagnóstico",
        onclick: async () => {
          try {
            await N.descargar("/api/mantenimiento/diagnostico", "diagnostico-natxajo.json");
          } catch (fallo) {
            if (!esSesionCaducada(fallo)) N.aviso("error", "No se pudo exportar", fallo.message);
          }
        },
      });
      N.pintar(main, [cabecera("Mantenimiento", "Diagnóstico de la plataforma y limpieza de archivos temporales antiguos.", N.el("div", { class: "acciones" }, descargar, botonRefrescar(ctx))), zona]);
      cargarEn(zona, () => N.api("GET", "/api/mantenimiento"), (datos) => {
        const comprobaciones = N.tabla({
          id: "mantenimiento-comprobaciones",
          buscar: false,
          columnas: [
            { clave: "nombre", titulo: "Comprobación" },
            { clave: "estado", titulo: "Estado", render: (f) => N.estadoComprobacion(f.estado) },
            { clave: "detalle", titulo: "Detalle", envolver: true },
          ],
          filas: datos.comprobaciones,
        });
        return [
          N.el("div", { class: "rejilla" },
            N.panel({ titulo: "Diagnóstico", sub: `Estado global: ${N.texto(datos.estado)}`, sinRelleno: true, cuerpo: comprobaciones }),
            N.panel({ titulo: "Limpieza de temporales", sub: "Planificar no borra nada", cuerpo: vistaLimpieza(ctx) })),
        ];
      });
    },
  });

  function vistaLimpieza(ctx) {
    const horas = N.el("input", { id: "horas", type: "number", min: "1", max: "720", value: "24", inputmode: "numeric" });
    const resultado = N.el("div", { class: "columna", role: "status" });
    let plan = null;
    const planificar = async () => {
      try {
        plan = await N.api("GET", "/api/mantenimiento/limpieza", { query: { horas: horas.value } });
        const archivos = plan.archivos;
        N.pintar(resultado, [
          archivos.length
            ? N.alerta("aviso", `${N.numero(archivos.length)} archivos temporales cumplen el criterio de más de ${plan.horas} horas.`)
            : N.alerta("ok", "No hay archivos temporales que limpiar con este criterio."),
          archivos.length ? N.el("ul", { class: "lista-simple" }, archivos.slice(0, 50).map((ruta) => N.el("li", null, N.el("span", { class: "mono", text: ruta })))) : null,
        ]);
      } catch (fallo) {
        if (!esSesionCaducada(fallo)) N.pintar(resultado, [N.alerta("peligro", fallo.message)]);
      }
    };
    const aplicar = async () => {
      const horasElegidas = Number(horas.value) || 24;
      await ejecutarSeguro(
        () => N.accionCritica((confirmado) => N.api("POST", "/api/acciones/mantenimiento/limpiar", { cuerpo: { horas: horasElegidas, confirmado } }), {
          titulo: "Limpiar archivos temporales",
          texto: `Se borrarán los archivos temporales de más de ${horasElegidas} horas en las carpetas que gestiona la plataforma.`,
          etiqueta: "Limpiar",
        }),
        { exito: { titulo: "Limpieza aplicada", detalle: (r) => `Eliminados ${r.eliminados} de ${r.planeados}` + (r.fallidos ? `. No se pudieron eliminar ${r.fallidos}: revise sus permisos` : "") }, titulo: "No se pudo limpiar" }
      );
      plan = null;
      N.pintar(resultado, []);
    };
    return N.el(
      "div",
      { class: "columna" },
      N.el("div", { class: "filtros" },
        N.el("div", { class: "campo" }, N.el("label", { for: "horas", text: "Antigüedad mínima (horas)" }), horas),
        N.el("button", { class: "btn", type: "button", text: "Planificar", onclick: planificar }),
        N.el("button", { class: "btn btn-peligro", type: "button", text: "Aplicar limpieza (crítica)", onclick: aplicar })),
      N.el("p", { class: "ayuda muted", text: "Solo se borran archivos temporales antiguos de las carpetas gestionadas. Revise el plan antes de aplicar." }),
      resultado
    );
  }

  /* ---- Configuración ----------------------------------------------------------------------- */

  const ETIQUETAS_TEMA = { oscuro: "Oscuro (corporativo)", claro: "Claro" };
  const ETIQUETAS_DENSIDAD = { comoda: "Cómoda", compacta: "Compacta" };
  const ETIQUETAS_MOVIMIENTO = { normal: "Normal", reducido: "Reducido" };
  const ETIQUETAS_ACTUALIZACION = { 0: "Manual", 30: "Cada 30 segundos", 60: "Cada minuto", 300: "Cada 5 minutos" };

  function opcionesTexto(valores, etiquetas) {
    return valores.map((valor) => ({ valor: String(valor), texto: etiquetas[valor] || String(valor) }));
  }

  registrar("configuracion", {
    titulo: "Configuración",
    icono: "configuracion",
    descripcion: "Preferencias visuales de esta interfaz e información del sistema.",
    render(main, ctx) {
      const zona = N.el("div", { class: "columna" });
      N.pintar(main, [cabecera("Configuración", "Preferencias visuales de esta interfaz e información del sistema.", botonRefrescar(ctx)), zona]);
      cargarEn(zona, () => N.api("GET", "/api/configuracion"), (datos) => {
        const p = datos.preferencias;
        const o = datos.opciones;
        const error = N.el("div", { class: "alerta peligro", role: "alert", hidden: true });
        const campos = {
          tema: N.campo({ id: "tema", etiqueta: "Tema", opciones: opcionesTexto(o.temas, ETIQUETAS_TEMA), valor: p.tema }),
          densidad: N.campo({ id: "densidad", etiqueta: "Densidad", opciones: opcionesTexto(o.densidades, ETIQUETAS_DENSIDAD), valor: p.densidad }),
          movimiento: N.campo({ id: "movimiento", etiqueta: "Animaciones", opciones: opcionesTexto(o.movimientos, ETIQUETAS_MOVIMIENTO), valor: p.movimiento }),
          pagina_inicio: N.campo({
            id: "pagina_inicio",
            etiqueta: "Página de inicio",
            opciones: o.paginas.map((id) => ({ valor: id, texto: N.paginas[id] ? N.paginas[id].titulo : id })),
            valor: p.pagina_inicio,
          }),
          actualizacion_segundos: N.campo({ id: "actualizacion_segundos", etiqueta: "Actualización automática", opciones: opcionesTexto(o.actualizaciones, ETIQUETAS_ACTUALIZACION), valor: String(p.actualizacion_segundos) }),
          filas_por_pagina: N.campo({ id: "filas_por_pagina", etiqueta: "Filas por página", opciones: opcionesTexto(o.filas, {}), valor: String(p.filas_por_pagina) }),
        };
        const notificaciones = N.el("input", { id: "notificaciones", type: "checkbox", checked: p.notificaciones ? true : null });
        const formulario = N.el(
          "form",
          {
            class: "columna",
            onsubmit: async (evento) => {
              evento.preventDefault();
              error.hidden = true;
              const cuerpo = {
                tema: campos.tema.querySelector("select").value,
                densidad: campos.densidad.querySelector("select").value,
                movimiento: campos.movimiento.querySelector("select").value,
                pagina_inicio: campos.pagina_inicio.querySelector("select").value,
                actualizacion_segundos: Number(campos.actualizacion_segundos.querySelector("select").value),
                filas_por_pagina: Number(campos.filas_por_pagina.querySelector("select").value),
                notificaciones: notificaciones.checked,
              };
              try {
                const guardadas = await N.api("POST", "/api/preferencias", { cuerpo });
                N.aplicarPreferencias(guardadas.preferencias);
                N.aviso("ok", "Preferencias guardadas");
              } catch (fallo) {
                if (esSesionCaducada(fallo)) return;
                error.textContent = fallo.message;
                error.hidden = false;
              }
            },
          },
          error,
          N.el("div", { class: "rejilla" }, Object.values(campos)),
          N.el("label", { class: "casilla", for: "notificaciones" }, notificaciones, N.el("span", { text: "Mostrar avisos informativos (los errores siempre se muestran)" })),
          N.el("div", { class: "acciones" }, N.el("button", { class: "btn btn-primario", type: "submit", text: "Guardar preferencias" }))
        );
        const sistema = N.ficha([
          ["Versión", datos.version],
          ["Estado del núcleo", datos.estado_nucleo],
          ["Servicios", N.numero(datos.servicios)],
          ["Python", datos.python],
          ["SQLite", datos.sqlite],
          ["Sistema", datos.sistema],
        ]);
        const sesion = N.estado.sesion || {};
        return [
          datos.aviso_preferencias ? N.alerta("aviso", datos.aviso_preferencias) : null,
          N.el("div", { class: "rejilla principal" },
            N.panel({ titulo: "Preferencias de la interfaz", sub: "Se guardan en config/interfaz.json", cuerpo: formulario }),
            N.el("div", { class: "columna" },
              N.panel({ titulo: "Sistema", cuerpo: sistema }),
              N.panel({ titulo: "Sesión", cuerpo: N.ficha([["Usuario", sesion.usuario], ["Empresa", sesion.empresa]]) }))),
        ];
      });
    },
  });

  /* Funciones que usan otras partes de la aplicación. */
  N.pedirTexto = pedirTexto;
  N.detalleGenerico = detalleGenerico;
})();
