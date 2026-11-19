# API y matriz de cobertura RF

Esta matriz corresponde al corte implementado en la rama del PR #38. “Implementado” significa que existe código y una ruta o flujo asociado; no significa que el Issue haya sido aceptado o deba cerrarse. Los 35 Issues siguen abiertos hasta revisar sus criterios con el responsable del proyecto.

## Acceso y formato

- Base local: `http://127.0.0.1:8000`.
- OpenAPI y Swagger UI: `/openapi.json` y `/docs` fuera de producción.
- Excepto `GET /health` y `POST /auth/login`, las rutas requieren `Authorization: Bearer <JWT>`.
- Roles: `admin`, `analyst`, `viewer`; solo los permisos listados por la API pueden modificar el estado.
- Errores de validación devuelven HTTP 422 con ID de solicitud y auditan nombres de campos, nunca valores del cuerpo.
- Los endpoints `/integrations/*` reciben lotes en el esquema normalizado de GUARDIÁN CARIBE. Usan JWT de usuario `analyst` o `admin`; no son conectores de proveedor ni claves de servicio.

## Cobertura de los requisitos

| RF | API o flujo implementado | Evidencia/próxima validación |
|---|---|---|
| 01 Autenticación segura | `POST /auth/login` | Argon2id, mensajes genéricos y token revocable; pruebas de login |
| 02 Cierre de sesión | `POST /auth/logout` | Revoca el `jti`; rutas privadas rechazan ese token |
| 03 Gestión de usuarios | `GET/POST /users`, `PATCH/DELETE /users/{id}` | Roles, activación y protección del último administrador |
| 04 Roles y permisos | Dependencias RBAC en rutas | Acceso no autorizado devuelve 403; cambios auditados |
| 05 Política de contraseñas | `PASSWORD_MIN_LENGTH`, `PUT/DELETE /system/config/{key}` | Longitud mínima configurable desde 12; alta de usuarios la aplica |
| 06 Bloqueo por intentos | `POST /auth/login` | Umbral y duración configurables; fallos producen evento sin guardar la contraseña |
| 07 Registro de eventos | `POST /events`, `POST /integrations/events` | ID interno, origen, fecha, severidad y datos permitidos |
| 08 Validación de eventos | Modelo `EventCreate` | Tipos, zona horaria, IP, hash, dominio y campos extra; fallos auditados |
| 09 Normalización | Ingesta de eventos | IP, dominio, hash y URL normalizados; fuente conservada; campos desconocidos rechazados |
| 10 Consulta de eventos | `GET /events`, `GET /events/{id}` | Listado paginado, detalle y permisos por rol |
| 11 Filtros de eventos | `GET /events` | Filtros combinables por tipo, severidad, fuente, IoC y tiempo |
| 12 Fallos repetidos | Detección de `login_failed` | Ventana/umbral configurables, alerta con IP y cantidad; comprobar con datos autorizados |
| 13 Actividad anómala | `POST/PATCH/GET /rules` y evaluación en ingesta | Reglas exactas/contiene generan alerta y evidencia enlazada |
| 14 Reglas de detección | `/rules` | Condición, severidad, activación y auditoría |
| 15 Solicitudes abusivas | Middleware HTTP | `429`, evento, auditoría y alerta agrupada con enfriamiento |
| 16 Generación de alertas | Correlación de IoC, reglas y fallos | Deduplicación temporal configurable; eventos repetidos se conservan como evidencia |
| 17 Clasificación | `PATCH /alerts/{id}` | Severidades definidas; cambio queda auditado |
| 18 Asignación | `PATCH /alerts/{id}` | Requiere usuario activo y registra antes/después |
| 19 Estado de alerta | `GET/PATCH /alerts/{id}` | Transiciones controladas y actor/fecha/detalles en auditoría |
| 20 Detalle de alerta | `GET /alerts/{id}` | IoC, evento original y eventos de evidencia enlazados |
| 21 Gestión de incidentes | `POST /incidents` | Incidente enlazable a una alerta y con estado inicial |
| 22 Seguimiento | `GET/PATCH /incidents/{id}` | Estado/asignación y cambios visibles en historial |
| 23 Notas | `POST /incidents/{id}/notes`, detalle del incidente | Notas anexas, con autor/fecha; no se sobrescriben |
| 24 Indicadores | `POST/GET /indicators`, `POST /integrations/indicators` | IP, dominio, URL, hash, procedencia, confianza y caducidad |
| 25 Consulta de IoC | `GET /indicators/search` | Búsqueda exacta devuelve `found`, `count` y `matches` |
| 26 Panel | `GET /analytics/summary?hours=...` | Eventos, alertas, incidentes y ventana seleccionada |
| 27 Reportes | `GET /reports/summary` | Periodo, fecha de generación, filtros y conteos |
| 28 Exportación | `GET /reports/export` | CSV/JSON con filtros; escape de fórmulas y metadatos de descarga |
| 29 Auditoría | `GET /audit` | Filtros por actor, acción, recurso y periodo; sin ruta de edición/borrado |
| 30 Configuración | `GET/PUT /system/config`, `DELETE /system/config/{key}` | Parámetros validados, persistentes y auditados; sin exponer secretos |
| 31 Entorno | `.env`, `config/.env.example`, `Settings` | Entorno identificado; secretos reales fuera del repositorio |
| 32 Errores operativos | `GET /operations/errors` | Errores internos y validaciones consultables por administradores sin datos del cuerpo |
| 33 Respaldo/restauración | `POST/GET /maintenance/backups`, CLI offline | Verificación SQLite; confirmación de reemplazo; restauración deja auditoría |
| 34 Límite de solicitudes | Configuración por cliente/IP de instancia única | Métrica y alerta; no coordina múltiples réplicas |
| 35 Pruebas | Pytest y workflow CI | Suite local y matriz Python 3.11/3.12; revisar resultado del commit final |

## Integraciones externas pendientes

El API permite que un conector de terceros envíe eventos/IoC normalizados por lotes. No realiza llamadas salientes a feeds ni a consolas EDR. Para esos conectores falta seleccionar proveedor y versión de API, definir campos y permisos, y entregar credenciales de prueba mediante secretos del entorno. No se debe cerrar RF ni dar por integrada una fuente hasta validar esos intercambios con el proveedor elegido.

Agentes EDR, feeds comerciales, aislamiento/respuesta automática, interfaz web y operación de varias instancias siguen fuera de este corte. Producción continúa bloqueada hasta completar controles de operación y revisar las migraciones en un entorno de despliegue.
