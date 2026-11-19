# Arquitectura y seguridad del prototipo

## Flujo

1. El cliente autenticado envía telemetría estructurada a `POST /events`.
2. Pydantic valida campos, fechas con zona horaria, IP, dominio, hash, longitud y severidad.
3. La API almacena evento normalizado y metadatos mínimos.
4. Reglas exactas comparan IP/dominio/hash con IoC vigentes. Otra regla agrupa fallos de autenticación por IP en una ventana temporal.
5. Las coincidencias producen alertas que un analista puede asignar, investigar, escalar o cerrar.
6. Las acciones relevantes crean registros de auditoría.

## Límites de confianza

- La API confía en el usuario autenticado para declarar el `source` del evento; el prototipo no prueba identidad criptográfica del agente.
- `details` acepta escalares para reducir cargas anidadas y se limita a 40 campos; no se deben enviar credenciales, tokens ni contenido personal innecesario.
- El modo local utiliza SQLite y un limitador por proceso. No es apropiado para varias réplicas.
- Las fuentes de inteligencia son declaradas por un administrador. El nombre, enlace, confianza y expiración permiten revisión; no certifican la calidad del feed.

## Controles

- Hash Argon2id y respuestas de login no reveladoras.
- JWT HS256 con clave configurada de al menos 32 caracteres, expiración, emisor y `jti` para revocación.
- RBAC aplicado en cada endpoint y bloqueo temporal por fallos de inicio de sesión.
- Consultas con parámetros, ORM y validación de entradas; rate limit de aplicación en el prototipo.
- No registra contraseñas ni tokens en logs de aplicación.

## Pendiente antes de un piloto con datos reales

Usar TLS y PostgreSQL gestionado; mover secretos a un gestor; incorporar migraciones; cifrar backups; acordar retención y jurisdicción de datos; proteger el plano de administración; usar una caché compartida para bloqueo/rate-limit; agregar pruebas de carga, revisión de dependencias y análisis de seguridad; validar conectores y reglas con telemetría sintética y datos de laboratorio. No conectar a producción ni ejecutar acciones automáticas contra endpoints con esta versión.
