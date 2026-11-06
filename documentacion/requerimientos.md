# Catálogo de requerimientos funcionales — GUARDIÁN CARIBE-V1

Este documento reúne los 35 requerimientos funcionales del proyecto. Cada requerimiento está registrado como un GitHub Issue individual e incluye historia de usuario, criterios de aceptación y prioridad.

| Código | Requerimiento | Prioridad | Issue |
|---|---|---|---|
| RF-01 | Autenticación segura | Alta | [#1](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/1) |
| RF-02 | Cierre de sesión | Alta | [#2](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/2) |
| RF-03 | Gestión de usuarios | Alta | [#3](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/3) |
| RF-04 | Roles y permisos | Alta | [#4](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/4) |
| RF-05 | Política de contraseñas | Media | [#5](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/5) |
| RF-06 | Bloqueo por intentos fallidos | Alta | [#6](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/6) |
| RF-07 | Registro de eventos | Alta | [#7](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/7) |
| RF-08 | Validación de eventos | Alta | [#8](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/8) |
| RF-09 | Normalización de eventos | Media | [#9](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/9) |
| RF-10 | Consulta de eventos | Alta | [#10](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/10) |
| RF-11 | Filtros de eventos | Media | [#11](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/11) |
| RF-12 | Detección de fallos repetidos | Alta | [#12](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/12) |
| RF-13 | Detección de actividad anómala | Alta | [#13](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/13) |
| RF-14 | Reglas de detección | Alta | [#14](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/14) |
| RF-15 | Detección de solicitudes abusivas | Alta | [#15](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/15) |
| RF-16 | Generación de alertas | Alta | [#16](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/16) |
| RF-17 | Clasificación de alertas | Media | [#17](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/17) |
| RF-18 | Asignación de alertas | Media | [#18](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/18) |
| RF-19 | Estado de alertas | Alta | [#19](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/19) |
| RF-20 | Detalle de alerta | Alta | [#20](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/20) |
| RF-21 | Gestión de incidentes | Alta | [#21](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/21) |
| RF-22 | Seguimiento de incidentes | Alta | [#22](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/22) |
| RF-23 | Notas de investigación | Media | [#23](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/23) |
| RF-24 | Indicadores de compromiso | Media | [#24](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/24) |
| RF-25 | Consulta de IoC | Media | [#25](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/25) |
| RF-26 | Panel de monitoreo | Media | [#26](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/26) |
| RF-27 | Reportes de seguridad | Media | [#27](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/27) |
| RF-28 | Exportación de reportes | Media | [#28](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/28) |
| RF-29 | Auditoría de acciones | Alta | [#29](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/29) |
| RF-30 | Configuración del sistema | Media | [#30](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/30) |
| RF-31 | Configuración por entorno | Alta | [#31](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/31) |
| RF-32 | Registro de errores operativos | Alta | [#32](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/32) |
| RF-33 | Respaldo y restauración | Alta | [#33](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/33) |
| RF-34 | Control de solicitudes abusivas | Alta | [#34](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/34) |
| RF-35 | Pruebas automatizadas | Crítica | [#35](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/35) |

## Plantilla aplicada a cada Issue

Cada Issue se redacta con los siguientes elementos:

1. **Historia de usuario:** Como [tipo de usuario], quiero [acción], para [beneficio].
2. **Criterios de aceptación:** condiciones verificables que permiten determinar cuándo el requerimiento satisface lo solicitado.
3. **Prioridad:** Crítica, Alta o Media.
4. **Identificación:** código RF correspondiente y vínculo con este catálogo.

## Clasificación mediante Labels

Los Issues se clasifican mediante etiquetas para facilitar su búsqueda y seguimiento:

- `enhancement`: funcionalidad o mejora propuesta.
- `Requerimiento`: identifica el tipo de elemento.
- `historia-usuario`: indica que el Issue contiene una historia de usuario.
- `prioridad-alta`: requerimientos de prioridad alta.
- `prioridad-media`: requerimientos de prioridad media.
- `prioridad-critica`: requerimientos de prioridad crítica.

Cada Issue debe conservar su etiqueta de prioridad correspondiente y las etiquetas generales aplicables.

## Relación con GitHub Projects

Los Issues son los registros originales de los requerimientos. Para que el tablero represente el avance, cada Issue debe agregarse al GitHub Project GUARDIÁN CARIBE-V1 como elemento existente; no se deben crear tarjetas independientes que dupliquen los Issues.

Estados definidos para el seguimiento:
- Pendiente.
- En proceso.
- En revisión.
- Completado.

La pertenencia de cada Issue al tablero debe comprobarse visualmente en GitHub Projects.
