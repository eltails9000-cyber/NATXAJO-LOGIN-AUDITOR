/* NATXAJO · núcleo de la interfaz: estado, llamadas a la API, construcción segura del DOM,
   diálogos (modal, confirmación, reautenticación) y avisos. Ningún dato del servidor se inserta
   como HTML: todo pasa por textContent o por nodos creados aquí. */
(() => {
  "use strict";

  const N = (window.NATXAJO = window.NATXAJO || {});
  const SVG_NS = "http://www.w3.org/2000/svg";

  N.estado = {
    csrf: "",
    sesion: null,
    preferencias: null,
    opciones: null,
    tablas: new Map(),
    pagina: null,
    temporizador: null,
    modalAbierto: false,
    cerrarModal: null,
  };

  class ErrorApi extends Error {
    constructor(status, codigo, mensaje) {
      super(mensaje);
      this.name = "ErrorApi";
      this.status = status;
      this.codigo = codigo;
    }
  }
  N.ErrorApi = ErrorApi;

  /* ---- API ---------------------------------------------------------------------------------- */

  N.api = async function api(metodo, ruta, opciones = {}) {
    const url = new URL(ruta, location.origin);
    for (const [clave, valor] of Object.entries(opciones.query || {})) {
      if (valor !== undefined && valor !== null && valor !== "") {
        url.searchParams.set(clave, String(valor));
      }
    }
    const cabeceras = { Accept: "application/json" };
    const init = { method: metodo, headers: cabeceras, credentials: "same-origin", cache: "no-store" };
    if (metodo !== "GET") {
      cabeceras["Content-Type"] = "application/json";
      cabeceras["X-CSRF-Token"] = N.estado.csrf || "";
      init.body = JSON.stringify(opciones.cuerpo || {});
    }
    let respuesta;
    try {
      respuesta = await fetch(url, init);
    } catch (_error) {
      throw new ErrorApi(0, "red", "No hay conexión con el proceso de la interfaz.");
    }
    let datos = null;
    try {
      datos = await respuesta.json();
    } catch (_error) {
      datos = null;
    }
    if (datos && typeof datos.csrf === "string") {
      N.estado.csrf = datos.csrf;
    }
    if (!respuesta.ok) {
      const detalle = (datos && datos.error) || {};
      const error = new ErrorApi(
        respuesta.status,
        detalle.codigo || "error",
        detalle.mensaje || "Se produjo un error inesperado."
      );
      const credencialesIncorrectas = error.codigo === "credenciales";
      if (respuesta.status === 401 && !credencialesIncorrectas) {
        document.dispatchEvent(new CustomEvent("natxajo:sesion-caducada"));
      }
      throw error;
    }
    return datos;
  };

  N.descargar = async function descargar(ruta, nombre) {
    const respuesta = await fetch(new URL(ruta, location.origin), {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!respuesta.ok) {
      throw new ErrorApi(respuesta.status, "descarga", "No se pudo descargar el archivo.");
    }
    const blob = await respuesta.blob();
    const enlace = document.createElement("a");
    const direccion = URL.createObjectURL(blob);
    enlace.href = direccion;
    enlace.download = nombre;
    document.body.append(enlace);
    enlace.click();
    enlace.remove();
    setTimeout(() => URL.revokeObjectURL(direccion), 1000);
  };

  /* ---- DOM ---------------------------------------------------------------------------------- */

  N.el = function el(etiqueta, propiedades, ...hijos) {
    const nodo = document.createElement(etiqueta);
    if (propiedades) {
      for (const [clave, valor] of Object.entries(propiedades)) {
        if (valor === undefined || valor === null || valor === false) continue;
        if (clave === "class") {
          nodo.className = String(valor);
        } else if (clave === "text") {
          nodo.textContent = String(valor);
        } else if (clave.startsWith("on") && typeof valor === "function") {
          nodo.addEventListener(clave.slice(2), valor);
        } else if (clave === "dataset") {
          Object.assign(nodo.dataset, valor);
        } else {
          nodo.setAttribute(clave, valor === true ? "" : String(valor));
        }
      }
    }
    N.anadir(nodo, hijos);
    return nodo;
  };

  N.anadir = function anadir(nodo, hijos) {
    for (const hijo of hijos.flat(Infinity)) {
      if (hijo === null || hijo === undefined || hijo === false) continue;
      nodo.append(hijo instanceof Node ? hijo : document.createTextNode(String(hijo)));
    }
    return nodo;
  };

  N.icono = function icono(nombre, clase = "") {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", `icon ${clase}`.trim());
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const uso = document.createElementNS(SVG_NS, "use");
    uso.setAttribute("href", `#i-${nombre}`);
    svg.append(uso);
    return svg;
  };

  /* ---- Formato ------------------------------------------------------------------------------ */

  const FORMATO_FECHA = new Intl.DateTimeFormat("es-ES", { dateStyle: "medium", timeStyle: "short" });
  const FORMATO_NUMERO = new Intl.NumberFormat("es-ES");

  N.fecha = function fecha(iso) {
    if (!iso) return "—";
    const fecha = new Date(iso);
    return Number.isNaN(fecha.getTime()) ? String(iso) : FORMATO_FECHA.format(fecha);
  };

  N.numero = function numero(valor) {
    return typeof valor === "number" ? FORMATO_NUMERO.format(valor) : "—";
  };

  N.texto = function texto(valor) {
    if (valor === null || valor === undefined || valor === "") return "—";
    if (typeof valor === "boolean") return valor ? "Sí" : "No";
    if (Array.isArray(valor)) return valor.length ? valor.join(", ") : "—";
    if (typeof valor === "object") return JSON.stringify(valor);
    return String(valor);
  };

  /* ---- Avisos ------------------------------------------------------------------------------- */

  N.aviso = function aviso(tipo, titulo, detalle = "") {
    const prefs = N.estado.preferencias;
    if (tipo !== "error" && prefs && prefs.notificaciones === false) return;
    const contenedor = document.getElementById("avisos");
    if (!contenedor) return;
    const nodo = N.el(
      "div",
      { class: `aviso-flotante ${tipo}`, role: tipo === "error" ? "alert" : "status" },
      N.el("strong", { text: titulo }),
      detalle ? N.el("span", { text: detalle }) : null
    );
    contenedor.append(nodo);
    setTimeout(() => nodo.remove(), tipo === "error" ? 8000 : 5000);
  };

  /* ---- Modal -------------------------------------------------------------------------------- */

  const FOCUSABLES = 'button:not([disabled]), [href], input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])';

  N.modal = function modal({ titulo, cuerpo, pie, alCerrar, estatico = false }) {
    const anterior = document.activeElement;
    const capa = document.getElementById("capa-modal");
    let cerrado = false;
    const alTeclar = (evento) => {
      if (evento.key === "Escape") {
        evento.preventDefault();
        cerrar();
      } else if (evento.key === "Tab") {
        const elementos = [...dialogo.querySelectorAll(FOCUSABLES)];
        if (!elementos.length) return;
        const primero = elementos[0];
        const ultimo = elementos[elementos.length - 1];
        if (evento.shiftKey && document.activeElement === primero) {
          evento.preventDefault();
          ultimo.focus();
        } else if (!evento.shiftKey && document.activeElement === ultimo) {
          evento.preventDefault();
          primero.focus();
        }
      }
    };
    const cerrar = () => {
      if (cerrado) return;
      cerrado = true;
      document.removeEventListener("keydown", alTeclar, true);
      capa.replaceChildren();
      N.estado.modalAbierto = false;
      N.estado.cerrarModal = null;
      if (anterior && typeof anterior.focus === "function") anterior.focus();
      if (alCerrar) alCerrar();
    };
    const dialogo = N.el(
      "div",
      {
        class: "modal",
        role: "dialog",
        "aria-modal": "true",
        "aria-labelledby": "modal-titulo",
      },
      N.el(
        "header",
        { class: "modal-cabecera" },
        N.el("h2", { id: "modal-titulo", text: titulo }),
        N.el(
          "button",
          { class: "icon-btn", type: "button", "aria-label": "Cerrar", onclick: cerrar },
          N.icono("cerrar")
        )
      ),
      N.el("div", { class: "modal-cuerpo" }, cuerpo),
      pie ? N.el("footer", { class: "modal-pie" }, pie(cerrar)) : null
    );
    const fondo = N.el("div", {
      class: "capa",
      onclick: (evento) => {
        if (!estatico && evento.target === evento.currentTarget) cerrar();
      },
    });
    fondo.append(dialogo);
    capa.replaceChildren(fondo);
    N.estado.modalAbierto = true;
    N.estado.cerrarModal = cerrar;
    document.addEventListener("keydown", alTeclar, true);
    const inicial = dialogo.querySelector("input, select, textarea") || dialogo.querySelector(".btn");
    if (inicial) inicial.focus();
    return { cerrar, elemento: dialogo };
  };

  N.confirmar = function confirmar({ titulo, texto, etiqueta = "Confirmar", peligro = false, casilla = null }) {
    return new Promise((resolver) => {
      let marca = null;
      const cuerpo = [N.el("p", { class: "muted", text: texto })];
      if (peligro) {
        cuerpo.push(
          N.el(
            "div",
            { class: "alerta peligro" },
            N.icono("alerta"),
            N.el("span", {
              text: "Operación crítica: requiere confirmación y una reautenticación reciente.",
            })
          )
        );
      }
      if (casilla) {
        marca = N.el("input", { type: "checkbox", id: "confirmo-casilla" });
        cuerpo.push(N.el("label", { class: "casilla", for: "confirmo-casilla" }, marca, N.el("span", { text: casilla })));
      }
      N.modal({
        titulo,
        cuerpo,
        alCerrar: () => resolver(false),
        pie: (cerrar) => [
          N.el("button", {
            class: "btn",
            type: "button",
            onclick: () => {
              resolver(false);
              cerrar();
            },
            text: "Cancelar",
          }),
          N.el("button", {
            class: peligro ? "btn btn-peligro" : "btn btn-primario",
            type: "button",
            text: etiqueta,
            onclick: () => {
              if (marca && !marca.checked) return;
              resolver(true);
              cerrar();
            },
          }),
        ],
      });
    });
  };

  N.reautenticar = function reautenticar() {
    return new Promise((resolver) => {
      const campo = N.el("input", {
        type: "password",
        id: "reauth-contrasena",
        name: "contrasena",
        autocomplete: "current-password",
        required: true,
      });
      const error = N.el("div", { class: "alerta peligro", role: "alert", hidden: true });
      const boton = N.el("button", {
        class: "btn btn-primario",
        type: "submit",
        form: "form-reautenticar",
        text: "Reautenticar",
      });
      let cerrarModal = () => {};
      const formulario = N.el(
        "form",
        {
          id: "form-reautenticar",
          class: "campo",
          onsubmit: async (evento) => {
            evento.preventDefault();
            const contrasena = campo.value;
            if (!contrasena) {
              error.textContent = "Escriba su contraseña.";
              error.hidden = false;
              return;
            }
            boton.disabled = true;
            try {
              await N.api("POST", "/api/sesion/reautenticar", { cuerpo: { contrasena } });
              campo.value = "";
              resolver(true);
              cerrarModal();
            } catch (fallo) {
              campo.value = "";
              error.textContent =
                fallo.codigo === "credenciales" ? "Contraseña incorrecta." : fallo.message;
              error.hidden = false;
              campo.focus();
            } finally {
              boton.disabled = false;
            }
          },
        },
        N.el("label", { for: "reauth-contrasena", text: "Contraseña de su cuenta" }),
        campo,
        N.el("p", {
          class: "ayuda",
          text: "La reautenticación dura 5 minutos y solo se usa para operaciones críticas.",
        })
      );
      const { cerrar } = N.modal({
        titulo: "Reautenticar la sesión",
        cuerpo: [error, formulario],
        alCerrar: () => resolver(false),
        pie: (cerrar_) => [
          N.el("button", {
            class: "btn",
            type: "button",
            text: "Cancelar",
            onclick: () => {
              resolver(false);
              cerrar_();
            },
          }),
          boton,
        ],
      });
      cerrarModal = cerrar;
    });
  };

  /* Ejecuta una operación crítica: pide confirmación y, si el servicio exige reautenticación,
     la pide y reintenta una vez. Devuelve null si el usuario cancela. */
  N.accionCritica = async function accionCritica(ejecutar, { titulo, texto, etiqueta, casilla }) {
    const confirmado = await N.confirmar({ titulo, texto, etiqueta, peligro: true, casilla });
    if (!confirmado) return null;
    try {
      return await ejecutar(true);
    } catch (fallo) {
      if (fallo.codigo !== "reautenticacion_requerida") throw fallo;
      const reautenticado = await N.reautenticar();
      if (!reautenticado) return null;
      return ejecutar(true);
    }
  };

  /* ---- Rutas -------------------------------------------------------------------------------- */

  N.rutaActual = function rutaActual() {
    const bruto = location.hash.replace(/^#\/?/, "");
    const [pagina = "", consulta = ""] = bruto.split("?");
    return { pagina, query: Object.fromEntries(new URLSearchParams(consulta)) };
  };

  N.ir = function ir(pagina, query = {}) {
    const consulta = new URLSearchParams(
      Object.entries(query).filter(([, valor]) => valor !== "" && valor !== null && valor !== undefined)
    ).toString();
    location.hash = `#/${pagina}${consulta ? `?${consulta}` : ""}`;
  };

  /* Estado de tabla (orden y filtro) que sobrevive a los refrescos de la misma sesión. */
  N.estadoTabla = function estadoTabla(id) {
    if (!N.estado.tablas.has(id)) {
      N.estado.tablas.set(id, { clave: null, dir: "asc", filtro: "" });
    }
    return N.estado.tablas.get(id);
  };
})();
