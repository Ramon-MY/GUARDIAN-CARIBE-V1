# GUARDIÁN CARIBE-V1

Prototipo académico de una API XDR ligera para registrar telemetría de seguridad, correlacionar indicadores de amenaza y gestionar alertas. El diseño prioriza despliegues pequeños y permite añadir fuentes de inteligencia locales con procedencia y caducidad.

**Estado:** primera versión funcional del backend; no es una plataforma XDR de producción.

**Responsable del proyecto:** Ramón Martínez.
**Stack:** Python 3.11+, FastAPI, SQLAlchemy, Pydantic, SQLite para desarrollo, PostgreSQL previsto para despliegue.

## Funciones implementadas

- Cuentas con roles `admin`, `analyst` y `viewer`; contraseñas Argon2id.
- JWT de acceso con expiración, emisor, identificador revocable y logout efectivo.
- Bloqueo temporal por intentos fallidos y mensajes de autenticación genéricos.
- Alta, desactivación y consulta de usuarios por administradores.
- Ingestión validada de eventos; normaliza IP, dominio, hash y hora UTC.
- Consulta paginada de eventos con filtros por tipo, severidad, IP y rango temporal.
- Indicadores IP, dominio y hash con fuente, confianza y fecha de expiración. No se incluye una lista inventada de IoC ni se afirma que el prototipo consuma feeds externos.
- Correlación exacta contra IoC y alerta por repetición de fallos de autenticación.
- Reglas configurables de detección exacta/contiene por administradores.
- Gestión de alertas e incidentes, transiciones de estado, asignación y notas de investigación.
- Resumen de actividad, exportación CSV/JSON de reportes y consulta administrativa de auditoría.
- Límite de solicitudes por IP para instancia única.
- Copia SQLite con verificación y restauración offline que exige confirmación explícita.

## Arranque local

Requiere Python 3.11 o superior.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item config/.env.example .env
```

Edita `.env`: genera `JWT_SECRET` con `python -c "import secrets; print(secrets.token_urlsafe(48))"` y reemplaza las credenciales de ejemplo por una contraseña única de al menos 12 caracteres. No subas `.env` ni secretos reales.

```powershell
uvicorn guardian_caribe.main:app --app-dir src --reload
```

La API estará en `http://127.0.0.1:8000`; documentación interactiva en `/docs` solo fuera de producción. El administrador bootstrap se crea al iniciar por primera vez cuando se definen `BOOTSTRAP_ADMIN_USERNAME` y `BOOTSTRAP_ADMIN_PASSWORD`.

## API principal

Todas las rutas salvo `GET /health` y `POST /auth/login` requieren `Authorization: Bearer <token>`.

| Ruta | Acceso | Uso |
|---|---|---|
| `POST /auth/login`, `POST /auth/logout` | Público / usuario autenticado | Iniciar y revocar sesión |
| `GET/POST /users`, `DELETE /users/{id}` | Admin | Administrar cuentas |
| `POST /events`, `GET /events` | Admin, analyst / usuarios autenticados | Ingerir y consultar telemetría |
| `GET/POST /indicators` | Consulta autenticada / admin | Mantener inteligencia de amenazas con procedencia |
| `GET /alerts`, `PATCH /alerts/{id}` | Consulta autenticada / admin, analyst | Revisar, asignar y actualizar alertas |
| `GET /analytics/summary` | Usuario autenticado | Métricas de las últimas 24 horas |
| `/rules`, `/incidents`, `/incidents/{id}/notes` | Admin / admin, analyst | Reglas, seguimiento y bitácora de investigación |
| `GET /audit`, `GET /system/config` | Admin | Auditoría y configuración sin secretos |
| `GET /reports/summary`, `GET /reports/export` | Usuario autenticado | Resumen y exportación CSV/JSON limitada |
| `GET/POST /maintenance/backups` | Admin | Listar o descargar una copia de SQLite |

Ejemplo de evento:

```json
{
  "event_type": "connection_observed",
  "source": "edge-firewall",
  "occurred_at": "2026-11-18T15:00:00Z",
  "severity": "medium",
  "source_ip": "203.0.113.15",
  "domain": "example.org",
  "details": {"action": "blocked"}
}
```

Las direcciones del ejemplo pertenecen a rangos reservados para documentación. No las uses como IoC operativo.

## Desarrollo y verificación

```powershell
python -m pip install -e ".[dev]"
pytest
ruff check src tests scripts
```

Las pruebas cubren autenticación, roles, revocación, validación, ingestión, filtros y alertas por IoC y fuerza bruta. SQLite local permite empezar sin servicios externos.

Para restaurar una copia local, detén la API, comprueba el archivo y el destino, y confirma el reemplazo:

```powershell
guardian-restore-sqlite .\backups\guardian-<id>.sqlite3 .\guardian_caribe.db --confirm-replace
```

Restaura copias de la misma versión del esquema; el prototipo todavía no tiene migraciones.

## Seguridad y límites conocidos

- El limitador y el bloqueo residen en memoria/base local; se reinician con el proceso y no coordinan varias instancias. Para despliegue se requiere almacenamiento compartido (Redis) y límites en proxy.
- La expiración JWT no sustituye TLS; no publiques el servicio directamente a Internet.
- El prototipo no trae conectores de agentes/EDR, feeds comerciales, aislamiento de endpoints, respuesta automatizada, MFA ni una interfaz web.
- Las reglas de detección son deliberadamente pequeñas y explícitas. Requieren ajuste con datos autorizados para reducir falsos positivos.
- La copia API solo funciona con SQLite en archivo local y descarga datos del sistema, incluidos hashes de contraseñas y telemetría. Limita quién puede acceder a ella; en Linux la API crea el directorio con modo `0700` y las copias con `0600`. Para restaurar, detén el servicio y usa el comando local con la ruta de destino comprobada y `--confirm-replace`.
- Antes de producción hacen falta migraciones versionadas, PostgreSQL, gestión de secretos, TLS, protección CSRF si se añade sesión de navegador, política de retención, revisión de privacidad, copias cifradas y ejercicios de restauración.
- Configurar `APP_ENV=production` hace que el servicio se niegue a iniciar mientras no existan migraciones y controles operativos; esta versión no admite despliegue de producción.

## Requerimientos y estado

El catálogo de [35 requerimientos](documentacion/requerimientos.md) describe el objetivo completo. Esta entrega implementa un corte vertical verificable de autenticación/usuarios, ingesta/consulta, IoC, reglas, alertas, incidentes, notas, auditoría, reportes, copias SQLite y configuración básica. Conectores y despliegue real permanecen pendientes; los Issues no se consideran completados por existir código relacionado.

## Proyecto

- [Repositorio](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1)
- [Issues](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues)
- [PR de mockups #37](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/pull/37)
- [Catálogo de requerimientos](documentacion/requerimientos.md)
