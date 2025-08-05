# WinSwissKnife - La Navaja Suiza para Mantenimiento de Windows

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-blue.svg)
![Licencia](https://img.shields.io/badge/Licencia-MIT-green.svg)
![Estado](https://img.shields.io/badge/Estado-Estable-brightgreen)

**WinSwissKnife** es una completa y potente suite de mantenimiento para Windows 10 y 11, desarrollada íntegramente en PowerShell. Nace de la necesidad de tener una herramienta todo-en-uno que no solo sea funcional, sino que opere bajo una estricta filosofía de **seguridad, transparencia y control total del usuario**.

A diferencia de muchas herramientas comerciales que ocultan sus operaciones, WinSwissKnife es de código abierto y te informa de cada paso que da. Su interfaz tipo "Dashboard" está diseñada para ser clara, informativa y fácil de usar, tanto para usuarios avanzados como para profesionales de TI.

### Captura de Pantalla del Dashboard

![Dashboard Principal de WinSwissKnife](https://i.imgur.com/link_a_tu_captura.png)
*(Nota: Deberás reemplazar el enlace anterior con una URL a una captura de pantalla real de la herramienta en ejecución.)*

---

### Características Principales

La herramienta está organizada en módulos accesibles desde una única interfaz central:

* **📊 Dashboard Principal:**
    * **Panel de Estado del Sistema:** Muestra en todo momento información vital de tu equipo (SO, versión, fecha de instalación, CPU, RAM y discos físicos), cargada una sola vez al inicio para máxima eficiencia.
    * **Panel de Acciones:** Un menú dinámico y claro para navegar entre los diferentes módulos y submenús.
    * **Panel de Salida de Comandos:** Un log en tiempo real que muestra el resultado de cada operación, con un sistema de paginación para salidas de texto extensas.

* **🚀 Módulo de Diagnóstico y Optimización:**
    * Realiza un chequeo rápido del sistema y ofrece recomendaciones.
    * Optimiza tus unidades de disco de forma inteligente, aplicando **TRIM** a los SSD y **desfragmentación** a los HDD.
    * Gestiona los programas de inicio y los planes de energía.

* **🧹 Módulo de Limpieza Profunda:**
    * Calcula y reporta el espacio liberado tras cada operación.
    * Elimina archivos temporales del sistema y del usuario.
    * Limpia la caché, cookies e historial de navegadores compatibles (Edge, Chrome, Firefox) a través de un submenú dinámico.
    * Vacía la papelera de reciclaje de forma segura.

* **❤️ Módulo de Salud y Reparación:**
    * Ejecuta las herramientas nativas de Windows como **SFC** (`/scannow`) y **DISM** para verificar y reparar la integridad de los archivos del sistema.
    * Programa comprobaciones de disco (`CHKDSK`) en el próximo reinicio.
    * Diagnostica problemas con los controladores de dispositivos.

* **🛡️ Módulo de Seguridad y Redes:**
    * Inicia escaneos rápidos o completos con Microsoft Defender.
    * Gestiona el estado del Firewall de Windows y permite restaurarlo a sus valores por defecto.
    * Herramientas de red para limpiar la caché de DNS, reiniciar la pila TCP/IP y renovar la IP.

* **🛠️ Módulo de Herramientas Avanzadas (Uso con Precaución):**
    * Suite completa para el **Registro de Windows**:
        * Creación de respaldos completos.
        * Escaneo de entradas obsoletas (incluyendo claves "fantasma" sin nombre).
        * **Limpieza interactiva y segura**, con respaldo individual de cada clave antes de su eliminación.
    * Gestión de Puntos de Restauración del sistema.

---

### Requisitos Previos

* **Sistema Operativo:** Windows 10 o Windows 11.
* **PowerShell:** Versión 5.1 o superior (viene preinstalado en Windows 10 y 11).
* **Permisos:** El script **debe** ejecutarse con privilegios de Administrador.
* **Consola:** Se recomienda encarecidamente usar **Windows Terminal** para una experiencia visual óptima, ya que renderiza correctamente los caracteres de los bordes y la interfaz.

---

### Instalación y Uso

1.  **Descarga:**
    * Clona el repositorio: `git clone https://github.com/tu_usuario/tu_repositorio.git`
    * O descarga el archivo `.zip` desde GitHub y extráelo en una carpeta de tu elección (ej. `C:\Scripts`).

2.  **Política de Ejecución de PowerShell:**
    Por seguridad, PowerShell restringe la ejecución de scripts. Para permitir que WinSwissKnife se ejecute en la sesión actual de la consola, puedes usar el siguiente comando al abrir PowerShell:
    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    ```
    *(Esto aplica la política solo para la ventana actual de PowerShell, es el método más seguro para ejecutar scripts locales).*

3.  **Ejecución:**
    * Abre una terminal de PowerShell **como Administrador**.
    * Navega a la carpeta donde guardaste el script.
    * Ejecútalo escribiendo:
    ```powershell
    .\WinSwissKnife.ps1
    ```

---

### Filosofía y Arquitectura

Este proyecto se ha construido sobre tres pilares no negociables:

1.  **Control Total del Usuario:** Ninguna acción destructiva (borrado de archivos o claves de registro) es automática. El consentimiento explícito del usuario para cada paso crítico es mandatorio.
2.  **Transparencia Absoluta:** El script comunica claramente qué va a hacer antes de hacerlo y registra meticulosamente sus acciones y resultados en el panel de salida y en un archivo de log (`%TEMP%\WinSwissKnife_Log_...`).
3.  **Seguridad y Robustez por Defecto:** Las operaciones se implementan con múltiples capas de seguridad y manejo de errores (`try...catch`). La herramienta está diseñada para fallar de forma elegante, informando del problema en lugar de cerrarse inesperadamente.

---

### ¿Cómo Contribuir?

Las contribuciones son bienvenidas. Si tienes ideas para una nueva funcionalidad o encuentras un error, por favor, sigue estos pasos:

1.  Crea un "Fork" del repositorio.
2.  Crea una nueva rama para tu funcionalidad (`git checkout -b feature/NuevaCaracteristica`).
3.  Realiza tus cambios y haz "commit" (`git commit -m 'Añade NuevaCaracteristica'`).
4.  Haz "push" a tu rama (`git push origin feature/NuevaCaracteristica`).
5.  Abre un "Pull Request".

También puedes abrir un "Issue" para reportar un error o proponer una mejora.

