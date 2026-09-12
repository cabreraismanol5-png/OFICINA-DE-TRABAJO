# Oficina de Trabajo Virtual — v4.7.1

Versión de producción para Render con **Centro de Administración integrado directamente en la pantalla principal**.

## Cambio principal

Ya no es necesario abrir `admin.html`. Desde la pantalla principal se pulsa **⚙️ Acceso administrativo**, se abre el centro administrativo integrado y todo funciona en la misma URL raíz.

- Configuración inicial del administrador.
- Inicio de sesión administrativo.
- Usuarios: búsqueda, aprobación, revocación y reenvío de código.
- Usuarios conectados y estadísticas.
- Administradores.
- Configuración/prueba de correo.
- Auditoría.
- Cierre de sesión administrativo sin navegar a otra página.
- Se mantienen `/admin`, `/admin/` y `/admin.html` como rutas compatibles, pero el flujo recomendado es la pantalla principal.

## Render

Usa el `render.yaml` incluido y realiza un nuevo deploy. La aplicación escucha en el puerto `10000` en Render mediante `PORT` (y conserva compatibilidad con el valor inyectado por Render) y usa la base de datos SQLite configurada por el proyecto.


## v4.7.2 — Netlify + Render
- `public/` is the Netlify publish directory.
- `netlify.toml` proxies `/api/*` to the Render backend.
- Render keeps the Node/SQLite database and administrative API.
- `ALLOW_NETLIFY_ORIGIN=true` permits the Netlify frontend to call the Render API.
- If using a custom Netlify domain, set `FRONTEND_ORIGINS` in Render to that exact HTTPS origin.

Recommended deployment: connect this repository to Netlify with base directory left at the project root. Netlify will read `netlify.toml` and publish `public/`.
