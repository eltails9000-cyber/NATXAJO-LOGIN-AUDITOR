/* NATXAJO · aplicación: arranque, acceso, cierre de sesión, navegación lateral, enrutado de páginas,
   preferencias visuales y actualización automática. Toda la información llega de la API local. */
(() => {
  "use strict";

  const N = window.NATXAJO;
  const raiz = document.getElementById("app");
  const PAGINA_POR_DEFECTO = "panel";
  const ETIQUETAS_ACTUALIZACION = {
    0: "manual",
    30: "cada 30 segundos",
    60: "cada minuto",
    300: "cada 5 minutos",
  };

  /* Referencias del shell autenticado. Es null mientras se muestra la pantalla de acceso. */
  let shell = null;

  /* ---- Estado de sesión --------------------------------------------------------------------- */

  function sesionIniciada() {
    return Boolean(N.estado.sesion && N.estado.sesion.autenticado);
  }

  function accesoA(id) {
    const paginas = (N.estado.sesion && N.estado.sesion.paginas) || {};
    return paginas[id] || "sin_permiso";
  }

  function paginaInicio() {
    const prefs = N.estado.preferencias;
    return (prefs && prefs.pagina_inicio) || PAGINA_POR_DEFECTO;
  }

  /* Borra datos que pertenecen a una sesión concreta para que no pasen a la siguiente. */
  function reiniciarEstadoDeSesion() {
    N.estado.empresas = null;
    N.estado.seleccion = null;
    N.estado.tablas = new Map();
    N.estado.pagina = null;
    if (N.estado.cerrarModal) N.estado.cerrarModal();
  }

  /* ---- Preferencias visuales y actualización automática ------------------------------------- */

  N.aplicarPreferencias = function aplicarPreferencias(prefs) {
    const html = document.documentElement;
    html.dataset.tema = prefs.tema;
    html.dataset.densidad = prefs.densidad;
    html.dataset.movimiento = prefs.movimiento;
    N.estado.preferencias = prefs;
    programarActualizacion();
  };

  function detenerActualizacion() {
    if (N.estado.temporizador) clearInterval(N.estado.temporizador);
    N.estado.temporizador = null;
  }

  /* Cada refresco automático vuelve a leer la página actual a través de la API, y cada lectura
     queda auditada. Por eso el valor por defecto es manual. */
  function programarActualizacion() {
    detenerActualizacion();
    const segundos = (N.estado.preferencias && N.estado.preferencias.actualizacion_segundos) || 0;
    if (shell) {
      shell.indicador.textContent = `Actualización ${ETIQUETAS_ACTUALIZACION[segundos] || "manual"}`;
    }
    if (segundos > 0 && sesionIniciada()) {
      N.estado.temporizador = setInterval(() => {
        if (N.estado.modalAbierto || document.hidden) return;
        dibujarPagina();
      }, segundos * 1000);
    }
  }

  /* ---- Navegación y páginas ----------------------------------------------------------------- */

  function alternarMenu(abrir) {
    if (!shell) return;
    const abierto = typeof abrir === "boolean" ? abrir : !shell.app.classList.contains("menu-abierto");
    shell.app.classList.toggle("menu-abierto", abierto);
    shell.botonMenu.setAttribute("aria-expanded", String(abierto));
  }

  function cerrarMenu() {
    alternarMenu(false);
  }

  function puertaDeAcceso(definicion, acceso) {
    const motivo =
      acceso === "solo_plataforma"
        ? "Esta sección está reservada a la cuenta de la plataforma. Una cuenta de empresa solo ve sus propios datos."
        : "Su rol no incluye permisos de lectura para esta sección.";
    return N.el(
      "div",
      { class: "columna" },
      N.cabeceraPagina({ titulo: definicion.titulo, descripcion: definicion.descripcion }),
      N.panel({ titulo: "Acceso restringido", cuerpo: N.seccionNoDisponible({ motivo }) })
    );
  }

  /* Pinta la página indicada por la ruta. No reinicia el temporizador. */
  function dibujarPagina() {
    if (!shell || !sesionIniciada()) return;
    const { pagina, query } = N.rutaActual();
    // hasOwn: un hash como #/constructor no debe resolverse a una propiedad heredada.
    const definicion = Object.hasOwn(N.paginas, pagina) ? N.paginas[pagina] : null;
    if (!definicion) {
      N.ir(paginaInicio());
      return;
    }
    N.estado.pagina = definicion.id;
    shell.enlaces.forEach((enlace, id) => {
      if (id === definicion.id) enlace.setAttribute("aria-current", "page");
      else enlace.removeAttribute("aria-current");
    });
    document.title = `${definicion.titulo} · NATXAJO`;
    shell.titulo.textContent = definicion.titulo;
    const acceso = accesoA(definicion.id);
    if (acceso !== "ok") {
      N.pintar(shell.contenido, [puertaDeAcceso(definicion, acceso)]);
      return;
    }
    definicion.render(shell.contenido, { query, refrescar: dibujarPagina });
  }

  /* Cambio de página: pinta, reinicia la cadencia de actualización y sube al inicio. */
  function navegar() {
    if (!shell) return;
    dibujarPagina();
    programarActualizacion();
    window.scrollTo(0, 0);
  }

  function construirNavegacion() {
    return N.listaPaginas().map((definicion) => {
      const ruta = `#/${definicion.id}`;
      const acceso = accesoA(definicion.id);
      return { definicion, ruta, acceso };
    });
  }

  function montarShell() {
    const sesion = N.estado.sesion;
    const enlaces = new Map();
    const nav = N.el(
      "nav",
      { class: "nav", "aria-label": "Secciones" },
      construirNavegacion().map(({ definicion, ruta, acceso }) => {
        const enlace = N.el(
          "a",
          {
            href: ruta,
            title: definicion.descripcion,
            class: acceso === "ok" ? null : "restringida",
            onclick: (evento) => {
              cerrarMenu();
              if (location.hash === ruta) {
                evento.preventDefault();
                navegar();
              }
            },
          },
          N.icono(definicion.icono),
          N.el("span", { class: "etiqueta", text: definicion.titulo }),
          acceso === "ok" ? null : N.icono("candado", "candado")
        );
        enlaces.set(definicion.id, enlace);
        return enlace;
      })
    );
    const sidebar = N.el(
      "aside",
      { class: "sidebar", id: "lateral", "aria-label": "Navegación principal" },
      N.el(
        "div",
        { class: "marca" },
        N.el("div", { class: "marca-logo", "aria-hidden": "true", text: "N" }),
        N.el(
          "div",
          { class: "marca-texto" },
          N.el("strong", { text: "NATXAJO" }),
          N.el("span", { text: "Auditor de autenticación" })
        )
      ),
      nav,
      N.el(
        "div",
        { class: "pie-lateral" },
        N.el(
          "div",
          { class: "usuario" },
          sesion.usuario,
          N.el("small", { text: sesion.plataforma ? "Cuenta de plataforma" : `Empresa ${sesion.empresa}` })
        ),
        N.el(
          "button",
          { class: "btn btn-fantasma btn-pequeno", type: "button", onclick: cerrarSesion },
          N.icono("salir"),
          "Cerrar sesión"
        )
      )
    );
    const botonMenu = N.el(
      "button",
      {
        class: "icon-btn menu-btn",
        type: "button",
        "aria-label": "Abrir o cerrar el menú",
        "aria-controls": "lateral",
        "aria-expanded": "false",
        onclick: () => alternarMenu(),
      },
      N.icono("menu")
    );
    const titulo = N.el("h1");
    const indicador = N.el("span", { class: "estado-linea" });
    const contenido = N.el("main", { class: "contenido", id: "contenido", tabindex: "-1" });
    const topbar = N.el(
      "header",
      { class: "topbar" },
      botonMenu,
      N.el("span", { class: "migas", text: `NATXAJO · ${sesion.version || ""}`.trim() }),
      titulo,
      N.el("span", { class: "espacio" }),
      indicador
    );
    const app = N.el("div", { class: "app" }, sidebar, N.el("div", { class: "area" }, topbar, contenido));
    // El fondo oscurecido del menú móvil pertenece a .app, así que un clic directo ahí lo cierra.
    app.addEventListener("click", (evento) => {
      if (evento.target === app) cerrarMenu();
    });
    shell = { app, enlaces, titulo, indicador, contenido, botonMenu };
    N.pintar(raiz, app);
  }

  /* ---- Acceso ------------------------------------------------------------------------------- */

  function mostrarAcceso(datos) {
    shell = null;
    detenerActualizacion();
    document.title = "Acceso · NATXAJO";
    const pendiente = Boolean(datos.instalacion_pendiente);
    const mensaje = N.el("span");
    const error = N.el("div", { class: "alerta peligro", role: "alert", hidden: true }, N.icono("alerta"), mensaje);
    const campoUsuario = N.campo({
      id: "usuario",
      etiqueta: "Usuario",
      autocomplete: "username",
      maxlength: "40",
      required: true,
    });
    const campoContrasena = N.campo({
      id: "contrasena",
      etiqueta: "Contraseña",
      tipo: "password",
      autocomplete: "current-password",
      required: true,
    });
    const usuarioEl = campoUsuario.querySelector("input");
    const contrasenaEl = campoContrasena.querySelector("input");
    const boton = N.el("button", { class: "btn btn-primario", type: "submit", text: "Entrar" });

    const mostrarError = (texto) => {
      mensaje.textContent = texto;
      error.hidden = false;
    };

    const enviar = async (evento) => {
      evento.preventDefault();
      error.hidden = true;
      const usuario = usuarioEl.value.trim();
      const contrasena = contrasenaEl.value;
      if (!usuario || !contrasena) {
        mostrarError("Escriba su usuario y su contraseña.");
        return;
      }
      boton.disabled = true;
      try {
        const respuesta = await N.api("POST", "/api/sesion/entrar", { cuerpo: { usuario, contrasena } });
        contrasenaEl.value = "";
        iniciarSesion(respuesta);
      } catch (fallo) {
        contrasenaEl.value = "";
        mostrarError(fallo.codigo === "credenciales" ? "Usuario o contraseña incorrectos." : fallo.message);
        contrasenaEl.focus();
      } finally {
        boton.disabled = false;
      }
    };

    const formulario = N.el(
      "form",
      { class: "acceso-form", onsubmit: enviar },
      error,
      campoUsuario,
      campoContrasena,
      boton
    );
    if (pendiente) {
      usuarioEl.disabled = true;
      contrasenaEl.disabled = true;
      boton.disabled = true;
    }
    const tarjeta = N.el(
      "section",
      { class: "acceso-tarjeta", "aria-labelledby": "acceso-titulo" },
      N.el(
        "div",
        { class: "marca" },
        N.el("div", { class: "marca-logo", "aria-hidden": "true", text: "N" }),
        N.el(
          "div",
          { class: "marca-texto" },
          N.el("strong", { text: "NATXAJO" }),
          N.el("span", { text: "Auditor de autenticación" })
        )
      ),
      N.el(
        "div",
        null,
        N.el("h1", { id: "acceso-titulo", text: "Iniciar sesión" }),
        N.el("p", { class: "muted", text: "Acceda con su cuenta para usar el auditor." })
      ),
      pendiente
        ? N.alerta("aviso", "La instalación inicial no está completa. Complétela en la terminal y vuelva a abrir esta interfaz.")
        : null,
      formulario,
      N.el("p", { class: "muted mono", text: `Versión ${datos.version || "—"}` })
    );
    N.pintar(raiz, N.el("main", { class: "acceso" }, tarjeta));
    if (!pendiente) usuarioEl.focus();
  }

  function iniciarSesion(datos) {
    N.estado.sesion = datos;
    reiniciarEstadoDeSesion();
    N.aplicarPreferencias(datos.preferencias);
    montarShell();
    navegar();
  }

  async function cerrarSesion() {
    if (!sesionIniciada()) return;
    try {
      const datos = await N.api("POST", "/api/sesion/salir", { cuerpo: {} });
      detenerActualizacion();
      reiniciarEstadoDeSesion();
      N.estado.sesion = datos;
      N.aplicarPreferencias(datos.preferencias);
      mostrarAcceso(datos);
      N.aviso("ok", "Sesión cerrada", "Ha salido de la interfaz.");
    } catch (fallo) {
      // Si la sesión ya caducó, el aviso de caducidad ya ha vuelto al acceso.
      if (sesionIniciada()) N.aviso("error", "No se pudo cerrar la sesión", fallo.message);
    }
  }

  /* ---- Arranque ----------------------------------------------------------------------------- */

  async function arrancar(aviso = null) {
    try {
      const datos = await N.api("GET", "/api/sesion");
      N.estado.sesion = datos;
      N.aplicarPreferencias(datos.preferencias);
      if (datos.autenticado) {
        montarShell();
        navegar();
      } else {
        mostrarAcceso(datos);
      }
      if (aviso) N.aviso(aviso.tipo, aviso.titulo, aviso.detalle);
    } catch (_fallo) {
      N.pintar(
        raiz,
        N.el(
          "main",
          { class: "acceso" },
          N.el(
            "section",
            { class: "acceso-tarjeta" },
            N.alerta("peligro", "No se pudo conectar con el proceso de NATXAJO. Compruebe que sigue en marcha y recargue la página.")
          )
        )
      );
    }
  }

  /* La API responde 401 cuando la sesión caduca. Volvemos al acceso una sola vez: la primera
     respuesta limpia el estado, así que las siguientes no repiten el aviso. */
  document.addEventListener("natxajo:sesion-caducada", () => {
    if (!sesionIniciada()) return;
    detenerActualizacion();
    reiniciarEstadoDeSesion();
    shell = null;
    N.estado.sesion = null;
    arrancar({ tipo: "error", titulo: "La sesión ha caducado", detalle: "Inicie sesión de nuevo para continuar." });
  });

  window.addEventListener("hashchange", () => {
    if (sesionIniciada()) navegar();
  });

  document.addEventListener("keydown", (evento) => {
    if (evento.key === "Escape" && shell && shell.app.classList.contains("menu-abierto")) {
      cerrarMenu();
    }
  });

  arrancar();
})();
