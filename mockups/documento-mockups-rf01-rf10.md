# GUARDIÁN CARIBE-V1
## Documento de wireframes y mockups — RF-01 al RF-10

**Asignatura:** Gestión de Configuración de Software  
**Estudiante y responsable:** Ramón Martínez  
**Modalidad:** Proyecto individual  
**Repositorio:** [GUARDIAN-CARIBE-V1](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1)  
**Rama de trabajo:** `mockups`  
**Issue relacionado:** [#36 — Diseño de mockups de GUARDIÁN CARIBE](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/36)  
**Versión del documento:** 1.0

---

## 1. Descripción del sistema

GUARDIÁN CARIBE es una propuesta de sistema ligero de monitoreo, detección y respuesta ante amenazas e incidentes de ciberseguridad. Está orientado a facilitar el registro, la validación, la normalización y la consulta de eventos, así como la administración segura de usuarios y el control de acceso.

La interfaz debe priorizar la claridad, la seguridad, la facilidad de uso y el rendimiento en entornos con conectividad limitada. Los diseños de este documento representan una propuesta visual inicial para las primeras diez funcionalidades del catálogo de requerimientos.

## 2. Objetivo de los mockups

Representar de forma visual la organización de las pantallas principales asociadas a RF-01 hasta RF-10. Estos wireframes permiten revisar la distribución de los componentes, los controles disponibles, los mensajes del sistema y la navegación antes de desarrollar la interfaz definitiva.

Los wireframes incluidos son esquemáticos y funcionales. La versión visual de alta fidelidad se elaborará en Figma siguiendo el prompt de diseño asociado a esta actividad.

## 3. Criterios visuales generales

- **Nombre del producto:** GUARDIÁN CARIBE.
- **Estilo:** plataforma profesional de ciberseguridad, moderna, sobria y accesible.
- **Paleta sugerida:** azul marino como color principal, azul medio para acciones, verde para estados correctos, ámbar para advertencias y rojo para errores o amenazas.
- **Tipografía:** Inter, Roboto o equivalente sans serif.
- **Estructura:** menú lateral, barra superior, área de contenido y paneles de información.
- **Accesibilidad:** contraste suficiente, etiquetas visibles, mensajes claros y controles identificables.
- **Adaptabilidad:** escritorio como vista principal y diseño adaptable a tabletas.
- **Seguridad:** no mostrar contraseñas en texto plano; confirmar acciones sensibles y comunicar errores sin revelar información interna.

## 4. Listado de pantallas

| N.º | Pantalla | Requerimiento | Propósito |
|---:|---|---|---|
| 1 | Inicio de sesión seguro | RF-01 | Autenticar al usuario |
| 2 | Cierre de sesión | RF-02 | Confirmar y finalizar la sesión |
| 3 | Gestión de usuarios | RF-03 | Consultar, crear y administrar usuarios |
| 4 | Roles y permisos | RF-04 | Definir accesos por rol |
| 5 | Política de contraseñas | RF-05 | Configurar reglas de contraseñas |
| 6 | Bloqueo por intentos fallidos | RF-06 | Controlar intentos de acceso incorrectos |
| 7 | Registro de eventos | RF-07 | Capturar eventos de seguridad |
| 8 | Validación de eventos | RF-08 | Revisar integridad y campos obligatorios |
| 9 | Normalización de eventos | RF-09 | Unificar el formato de los eventos |
| 10 | Consulta de eventos | RF-10 | Buscar y revisar eventos registrados |

---

## 5. Wireframes y explicación de las pantallas

### Pantalla 01 — Inicio de sesión seguro
**Requerimiento asociado:** RF-01 — Autenticación segura.

**Objetivo:** permitir el acceso únicamente a usuarios registrados y autorizados.

**Elementos principales:** logotipo y nombre del sistema, campo de correo o nombre de usuario, campo de contraseña con opción para mostrar u ocultar, botón Iniciar sesión, enlace de recuperación si está habilitado y mensaje de error genérico.

**Wireframe:**

```
+--------------------------------------------------------------+
|                    GUARDIÁN CARIBE                           |
|             Plataforma de seguridad informática             |
|                                                              |
|                 +------------------------+                   |
|                 |     INICIAR SESIÓN     |                   |
|                 | Usuario / correo       |                   |
|                 | [____________________] |                   |
|                 | Contraseña             |                   |
|                 | [____________________] |                   |
|                 | [ ] Mostrar contraseña |                   |
|                 |                        |                   |
|                 | [    INICIAR SESIÓN  ] |                   |
|                 | ¿Problemas para entrar?|                   |
|                 +------------------------+                   |
|                                                              |
|                 Acceso protegido                              |
+--------------------------------------------------------------+
```

**Comportamiento esperado:** validar los campos, enviar las credenciales por un canal seguro y permitir el acceso solo si la autenticación es correcta. Los mensajes de error no deben revelar si una cuenta específica existe.

### Pantalla 02 — Cierre de sesión
**Requerimiento asociado:** RF-02 — Cierre de sesión.

**Objetivo:** permitir al usuario terminar su sesión de forma segura.

**Elementos principales:** menú de usuario, opción Cerrar sesión, cuadro de confirmación, botones Cancelar y Confirmar cierre.

**Wireframe:**

```
+--------------------------------------------------------------+
| GUARDIÁN CARIBE                 Usuario: Analista     [Perfil]|
+----------------------+---------------------------------------+
| Panel                |                                       |
| Eventos              |       ¿Desea cerrar su sesión?        |
| Alertas              |                                       |
| Usuarios             |   La sesión actual finalizará.        |
| Configuración        |                                       |
|                      |   [ CANCELAR ] [ CERRAR SESIÓN ]      |
+----------------------+---------------------------------------+
| Estado de sesión: Activa                                      |
+--------------------------------------------------------------+
```

**Comportamiento esperado:** solicitar confirmación cuando corresponda, invalidar la sesión en el servidor y redirigir al inicio de sesión. No debe dejar activa una sesión autenticada después del cierre.

### Pantalla 03 — Gestión de usuarios
**Requerimiento asociado:** RF-03 — Gestión de usuarios.

**Objetivo:** administrar las cuentas de las personas autorizadas a utilizar el sistema.

**Elementos principales:** título, botón Nuevo usuario, buscador, filtros por estado y rol, tabla con usuario, correo, rol, estado y acciones.

**Wireframe:**

```
+----------------------------------------------------------------+
| GUARDIÁN CARIBE / Administración / Usuarios                    |
+----------------------+-----------------------------------------+
| Menú lateral         | Gestión de usuarios     [ + Nuevo ]    |
|                      | Buscar: [____________________] [Buscar] |
|                      | Filtro estado: [Todos v] Rol: [Todos v] |
|                      |-----------------------------------------|
|                      | Usuario | Correo | Rol | Estado | Acción|
|                      | Ana     | ...    | Adm | Activo | [Ver] |
|                      | Luis    | ...    | Ana | Activo | [Ver] |
|                      | Marta   | ...    | Ana | Inactivo|[Ver] |
|                      |-----------------------------------------|
|                      |                         [Anterior][1][>]|
+----------------------+-----------------------------------------+
```

**Comportamiento esperado:** permitir crear, consultar, actualizar y desactivar usuarios según los permisos del administrador. Las acciones sensibles deben quedar sujetas a autorización y auditoría.

### Pantalla 04 — Roles y permisos
**Requerimiento asociado:** RF-04 — Roles y permisos.

**Objetivo:** controlar qué módulos y acciones puede utilizar cada tipo de usuario.

**Elementos principales:** listado de roles, descripción del rol seleccionado, matriz de permisos por módulo y acción, botones Guardar y Cancelar.

**Wireframe:**

```
+----------------------------------------------------------------+
| GUARDIÁN CARIBE / Administración / Roles y permisos            |
+----------------------+-----------------------------------------+
| Menú lateral         | Roles y permisos                        |
|                      | Rol seleccionado: [Analista v]          |
|                      |-----------------------------------------|
| Roles                | Módulo       Ver  Crear Editar Eliminar |
| [Administrador]      | Usuarios     [ ]  [ ]   [ ]    [ ]       |
| [Analista]           | Eventos      [x]  [ ]   [ ]    [ ]       |
| [Consulta]           | Alertas      [x]  [x]   [x]    [ ]       |
|                      | Reportes     [x]  [ ]   [ ]    [ ]       |
|                      |-----------------------------------------|
|                      | [ CANCELAR ]          [ GUARDAR ]       |
+----------------------+-----------------------------------------+
```

**Comportamiento esperado:** mostrar permisos asociados al rol, permitir cambios solo a usuarios autorizados y aplicar el principio de mínimo privilegio. Antes de guardar, validar que no se elimine accidentalmente el acceso administrativo esencial.

### Pantalla 05 — Política de contraseñas
**Requerimiento asociado:** RF-05 — Política de contraseñas.

**Objetivo:** definir reglas mínimas para crear y actualizar contraseñas seguras.

**Elementos principales:** longitud mínima, requisitos de mayúsculas, minúsculas, números y caracteres especiales, vigencia si aplica, historial de contraseñas y botón Guardar política.

**Wireframe:**

```
+----------------------------------------------------------------+
| GUARDIÁN CARIBE / Configuración / Política de contraseñas      |
+----------------------+-----------------------------------------+
| Menú lateral         | Reglas de contraseñas                   |
|                      | Longitud mínima:       [ 12 ]           |
|                      | [x] Incluir mayúsculas                  |
|                      | [x] Incluir minúsculas                  |
|                      | [x] Incluir números                     |
|                      | [x] Incluir símbolos                    |
|                      | Evitar últimas contraseñas: [ 5 ]       |
|                      | Vigencia (días):         [ 90 ]         |
|                      |                                        |
|                      | [ RESTABLECER ] [ GUARDAR POLÍTICA ]   |
+----------------------+-----------------------------------------+
```

**Comportamiento esperado:** validar los valores configurados, mostrar una explicación breve de cada regla y aplicar la política al crear o cambiar contraseñas. Los valores finales deberán ajustarse a la política de seguridad aprobada para el sistema.

### Pantalla 06 — Bloqueo por intentos fallidos
**Requerimiento asociado:** RF-06 — Bloqueo por intentos fallidos.

**Objetivo:** reducir intentos automatizados o repetidos de acceso no autorizado.

**Elementos principales:** umbral de intentos, duración del bloqueo, estado del control, tabla de eventos de bloqueo y acciones administrativas autorizadas.

**Wireframe:**

```
+----------------------------------------------------------------+
| GUARDIÁN CARIBE / Seguridad / Control de acceso                |
+----------------------+-----------------------------------------+
| Menú lateral         | Bloqueo por intentos fallidos            |
|                      | Máximo de intentos: [ 5 ]                |
|                      | Duración del bloqueo: [ 15 ] minutos     |
|                      | [x] Activar bloqueo automático           |
|                      |-----------------------------------------|
|                      | Cuenta/Origen | Intentos | Estado | Hora |
|                      | usuario A     |    5     | Bloq.  | ...  |
|                      | usuario B     |    2     | Normal | ...  |
|                      |-----------------------------------------|
|                      | [ GUARDAR CONFIGURACIÓN ]                |
+----------------------+-----------------------------------------+
```

**Comportamiento esperado:** contar los intentos fallidos, aplicar el bloqueo al alcanzar el umbral y registrar el evento. El desbloqueo manual, si está permitido, debe requerir autorización y quedar auditado.

### Pantalla 07 — Registro de eventos
**Requerimiento asociado:** RF-07 — Registro de eventos.

**Objetivo:** recibir o registrar eventos relevantes para la supervisión de seguridad.

**Elementos principales:** formulario de registro o fuente de ingreso, tipo de evento, fecha y hora, origen, descripción, nivel de severidad y botón Registrar evento.

**Wireframe:**

```
+----------------------------------------------------------------+
| GUARDIÁN CARIBE / Eventos / Registrar evento                   |
+----------------------+-----------------------------------------+
| Menú lateral         | Nuevo evento                            |
|                      | Tipo de evento: [Seleccionar v]         |
|                      | Fecha y hora:   [________________]      |
|                      | Origen/IP:      [________________]      |
|                      | Severidad:      [Baja v]                |
|                      | Descripción:                             |
|                      | [____________________________________]  |
|                      | [____________________________________]  |
|                      | Fuente:         [Manual v]              |
|                      |                                        |
|                      | [ CANCELAR ] [ REGISTRAR EVENTO ]      |
+----------------------+-----------------------------------------+
```

**Comportamiento esperado:** validar los campos obligatorios, asignar identificador y marca de tiempo, registrar el origen y conservar el evento para su procesamiento posterior.

### Pantalla 08 — Validación de eventos
**Requerimiento asociado:** RF-08 — Validación de eventos.

**Objetivo:** verificar que los eventos recibidos cumplan las reglas de integridad y estructura.

**Elementos principales:** resumen de eventos pendientes, resultado de validación, lista de errores, detalle del evento y acciones para aceptar o enviar a revisión.

**Wireframe:**

```
+----------------------------------------------------------------+
| GUARDIÁN CARIBE / Eventos / Validación                         |
+----------------------+-----------------------------------------+
| Menú lateral         | Validación de eventos                    |
|                      | Pendientes: 18  Válidos: 14  Errores: 4  |
|                      |-----------------------------------------|
|                      | ID   | Origen | Resultado | Acción      |
|                      | E01  | API    | Válido    | [Detalle]   |
|                      | E02  | Manual | Error     | [Revisar]   |
|                      | E03  | Syslog | Válido    | [Detalle]   |
|                      |-----------------------------------------|
|                      | Detalle de validación                    |
|                      | - Campo obligatorio ausente              |
|                      | - Formato de fecha incorrecto             |
|                      | [ RECHAZAR ] [ MARCAR PARA REVISIÓN ]     |
+----------------------+-----------------------------------------+
```

**Comportamiento esperado:** ejecutar las reglas de validación, identificar campos faltantes o formatos incorrectos y conservar el resultado para trazabilidad. Un evento inválido no debe tratarse como validado.

### Pantalla 09 — Normalización de eventos
**Requerimiento asociado:** RF-09 — Normalización de eventos.

**Objetivo:** convertir eventos de distintas fuentes a una estructura común para facilitar su análisis.

**Elementos principales:** selección de fuente, vista de datos originales, vista de campos normalizados, reglas aplicadas y resultado del proceso.

**Wireframe:**

```
+----------------------------------------------------------------+
| GUARDIÁN CARIBE / Eventos / Normalización                      |
+----------------------+-----------------------------------------+
| Menú lateral         | Normalizar eventos                      |
|                      | Fuente: [Syslog v]  [Cargar / Seleccionar]|
|                      |-----------------------------------------|
|                      | DATO ORIGINAL       CAMPO NORMALIZADO   |
|                      | src_ip: 10.0.0.5     origen_ip: 10.0.0.5 |
|                      | event: login_fail   tipo: acceso_fallido|
|                      | time: ...           fecha_hora: ...     |
|                      |-----------------------------------------|
|                      | Reglas aplicadas: 3                     |
|                      | Estado: Listo para procesar              |
|                      | [ VISTA PREVIA ] [ NORMALIZAR ]         |
+----------------------+-----------------------------------------+
```

**Comportamiento esperado:** mapear campos de origen a un esquema común, conservar referencia al dato original y mostrar errores o campos que no pudieron transformarse. La normalización no debe alterar ni eliminar la evidencia original.

### Pantalla 10 — Consulta de eventos
**Requerimiento asociado:** RF-10 — Consulta de eventos.

**Objetivo:** permitir localizar y consultar eventos registrados en el sistema.

**Elementos principales:** buscador, filtros por fecha, tipo, origen y severidad, tabla de resultados, paginación y vista de detalle.

**Wireframe:**

```
+----------------------------------------------------------------+
| GUARDIÁN CARIBE / Eventos / Consulta                           |
+----------------------+-----------------------------------------+
| Menú lateral         | Consultar eventos                       |
|                      | Buscar: [____________________] [Buscar] |
|                      | Desde: [____] Hasta: [____]              |
|                      | Tipo: [Todos v] Severidad: [Todas v]    |
|                      | Origen: [____________]                   |
|                      |-----------------------------------------|
|                      | Fecha | Tipo | Origen | Nivel | Acción  |
|                      | ...   | Login| ...    | Alto  | [Ver]   |
|                      | ...   | Red  | ...    | Medio | [Ver]   |
|                      | ...   | API  | ...    | Bajo  | [Ver]   |
|                      |-----------------------------------------|
|                      | Resultados: 24             [<] 1 [>]    |
+----------------------+-----------------------------------------+
```

**Comportamiento esperado:** aplicar los criterios de búsqueda, presentar resultados paginados y permitir consultar el detalle según los permisos del usuario. Si no existen coincidencias, mostrar un mensaje claro y permitir limpiar los filtros.

---

## 6. Relación entre pantallas y requerimientos

| Pantalla | Requerimiento | Issue existente |
|---|---|---|
| Inicio de sesión seguro | RF-01 | [#1](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/1) |
| Cierre de sesión | RF-02 | [#2](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/2) |
| Gestión de usuarios | RF-03 | [#3](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/3) |
| Roles y permisos | RF-04 | [#4](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/4) |
| Política de contraseñas | RF-05 | [#5](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/5) |
| Bloqueo por intentos fallidos | RF-06 | [#6](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/6) |
| Registro de eventos | RF-07 | [#7](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/7) |
| Validación de eventos | RF-08 | [#8](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/8) |
| Normalización de eventos | RF-09 | [#9](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/9) |
| Consulta de eventos | RF-10 | [#10](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/10) |

## 7. Navegación general propuesta

1. El usuario ingresa mediante la pantalla de autenticación (RF-01).
2. Una vez autenticado, accede a los módulos permitidos según su rol (RF-04).
3. El administrador gestiona usuarios y políticas de acceso (RF-03, RF-05 y RF-06).
4. Los eventos se registran, validan y normalizan (RF-07, RF-08 y RF-09).
5. Los usuarios autorizados consultan los eventos (RF-10).
6. El usuario finaliza su sesión de forma segura (RF-02).

## 8. Consideraciones y alcance

- Este documento constituye una propuesta de diseño; no representa una interfaz ya implementada.
- Los datos mostrados son ejemplos ilustrativos y no corresponden a información real.
- Los controles y reglas deberán validarse con los criterios de aceptación de cada requerimiento.
- Las pantallas de alta fidelidad de Figma podrán incorporarse como imágenes o enlaces en una revisión posterior del documento.
- Los diseños no deben exponer contraseñas, secretos, tokens ni datos sensibles.

## 9. Control de cambios

| Versión | Descripción | Responsable |
|---|---|---|
| 1.0 | Creación del documento de wireframes para RF-01 a RF-10 | Ramón Martínez |

## 10. Vinculación con GitHub

- **Issue de diseño:** [#36 — DISEÑO: Mockups de GUARDIÁN CARIBE (RF-01 a RF-10)](https://github.com/Ramon-MY/GUARDIAN-CARIBE-V1/issues/36)
- **Rama:** `mockups`
- **Pull Request:** se utilizará un PR desde `mockups` hacia `main`, relacionado con el Issue #36.
