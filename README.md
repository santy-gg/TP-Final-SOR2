# Eficacia y costo computacional de los modelos Mistral-7B y Phi-3 en la clasificación semántica de auditoría interna frente a amenazas multi-paso

Este repositorio contiene el código fuente, la configuración del entorno y la matriz de datos lógicos utilizados para el Trabajo Final de la materia **Sistemas Operativos y Redes 2 (Primer Semestre 2026)** de la Licenciatura en Sistemas en la **Universidad Nacional de General Sarmiento (UNGS)**.

El proyecto evalúa y contrasta la eficacia analítica (comprensión semántica) y el costo computacional (latencia) de dos Modelos de Lenguaje Extensos (LLMs) ejecutados de forma local (**Mistral 7B** y **Phi-3 Mini**) frente a un clasificador tradicional basado en **Expresiones Regulares (Regex)** para la detección de amenazas multi-paso en sistemas Linux.

---

## Estructura del Repositorio

* `evaluador_llm_mistral.py`/`evaluador_llm_phi3.py`: Script principal en Python que lee los registros de auditoría, estructura el prompt del sistema bajo un esquema estricto de respuesta JSON y despacha las peticiones HTTP por API.
* `clasificador_regex.py`: Módulo de control estático lineal que evalúa sintácticamente las cadenas de texto del log utilizando expresiones regulares tradicionales.
* `custom.rules`: Archivo con las directivas inyectadas en `/etc/audit/rules.d/` para vigilar la manipulación de `/etc/shadow`, `/etc/sudoers` y llamadas `execve` con privilegios de root.
* `V-ATK-01.txt`: Telemetría cruda simulando una intrusión coordinada multi-paso (escalada de privilegios).
* `V-ADM-01.txt`: Registros de mantenimiento administrativo legítimo de alta densidad (control de falsos positivos).
* `V-NRM-01.txt`, `V-NRM-02.txt`, `V-NRM-03.txt`: Logs de ruido cotidiano y actividad rutinaria del sistema operativo.
* `ground_truth.csv`: tabla con el resultado ideal de las pruebas.

---

## Funcionalidad del proyecto

El sistema opera como un pipeline automatizado de análisis forense diferido que procesa datos en tres etapas continuas:
* **Entradas:** utiliza archivos de texto plano (`.txt`) que contienen ráfagas secuenciales de logs crudos generados por el Kernel a través de `auditd`, segmentados en ventanas temporales estrictas de 3 minutos.
* **Procesamiento:** El pipeline en Python encapsula estos logs dentro de un prompt de sistema estructurado y los envía mediante peticiones HTTP a la API del modelo seleccionado. La IA analiza semánticamente las relaciones de los metadatos (`UID`, `EXE`) y las llamadas al sistema (*syscalls*) en el tiempo, distribuyendo la carga matemática de sus capas de forma híbrida entre la CPU y la GPU.
* **Resultados:** El modelo retorna un objeto estructurado en formato JSON que contiene un veredicto determinista del nivel de riesgo (**ALTO**, **MEDIO** o **BAJO**) junto con un párrafo explicativo del razonamiento forense aplicado, el cual es guardado y tabulado junto a las métricas de tiempo de ejecución.

---

## Instalación y configuración

### Requisitos de hardware y software
* **Host Físico:** Procesador AMD Ryzen 5 1600, Tarjeta Gráfica AMD Radeon RX 570 (4 GB VRAM) compatible con la API Vulkan.
* **Entorno de Inferencia:** LM Studio (v0.2+ o superior) configurado para exponer la API local en el puerto `1234`.
* **Máquina virtual:** Oracle VirtualBox ejecutando una Máquina Virtual con **Ubuntu Server** (sin interfaz gráfica, mínimo 2 GB RAM, red configurada en modo **Adaptador Puente / Bridged Adapter** para garantizar visibilidad en la misma subred del Host).

### Descarga de Modelos
* **LM Studio** configurado con los siguientes modelos en formato `.gguf`:
    * `Mistral-7B-Instruct-v0.3.Q4_K_M.gguf`
    * `Phi-3-mini-4k-instruct-q4.gguf`

### Comandos de Instalación (Dependencias en el Host)
Clonar el repositorio y cargar las librerías estándar requeridas (el pipeline utiliza módulos nativos y `requests` para el canal HTTP):

```bash
   git clone [https://github.com/santy-gg/TP-Final-SOR2.git](https://github.com/santy-gg/TP-Final-SOR2.git)
   cd TP-Final-SOR2
   pip install requests
```

---

## Uso y reproducción
El repositorio cuenta con scripts independientes para reproducir y evaluar cada uno de los enfoques experimentales de forma aislada.

* Para ejecutar Mistral 7B:
```bash
   python evaluador_llm_mistral.py
```
* Para ejecutar Phi-3 Mini:

```Bash
python evaluador_llm_phi3.py
```

* Para ejecutar el clasificador estático (Regex):
```bash
python evaluador_regex.py
```
## Ubicación de Datos
* Logs de Entrada: Se localizan en V-ATK-01.txt, V-ADM-01.txt, V-NRM-01.txt.

* Resultados de Salida: Los veredictos JSON junto con las bitácoras de tiempos calculadas por el pipeline se almacenan y exportan automáticamente dentro del directorio outputs/.

---

## Dataset y entorno experimental

### Origen y Generación de Logs
Los registros fueron capturados directamente del archivo activo de auditoría de la Máquina Virtual con Ubuntu Server. Para simular un entorno corporativo realista, se ejecutaron tres escenarios controlados bajo ventanas estrictas de 3 minutos:

1. *V-ATK-01 (Ataque multi-paso)*: Simula una intrusión remota vía SSH que ejecuta tácticas de reconocimiento, intentos de modificación de archivos críticos (/etc/shadow) y un intento de escalada de privilegios.

2. *V-ADM-01 (Mantenimiento legítimo)*: Ráfaga de alta densidad de comandos administrativos ejecutados por un SysAdmin (actualizaciones de paquetes, edición de sudoers, configuraciones), utilizado para evaluar la tasa de falsos positivos.

3. *V-NRM-01/V-NRM-02/V-NRM-03 (Ruido rutinario)*: Tres variantes independientes que registran la actividad básica y el ruido rutinario de usuarios comunes sin privilegios. Estas ventanas adicionales (02 y 03) fueron generadas con el propósito de aumentar la muestra de casos negativos dentro del modelo de control y robustecer la evaluación estadística.

### Reglas de auditd e Inyección en el Kernel
Para que el sistema operativo víctima genere los eventos específicos que el pipeline de Python analiza, se deben cargar las reglas personalizadas de auditoría:

1. Dentro de la máquina virtual, clonar este repositorio o transferir el archivo `custom.rules`.
2. Copiar el archivo de reglas al directorio correspondiente de `auditd`:
   ```bash
   sudo cp config/custom.rules /etc/audit/rules.d/custom.rules
3. Regenerar y cargar el set de reglas activo en el Kernel mediante el script nativo de automatización:
   ```Bash
      sudo augenrules --load
4. (Opcional) Verificar que las reglas se hayan inyectado correctamente en el sistema ejecutando:
   ```Bash
      sudo auditctl -l
Deberían listarse los filtros asociados a las claves (`-k`) de `passwd_changes`, `sudoers_changes` y `root_commands`.

### Ground Truth
El Ground Truth define los resultados ideales de cada ventana temporal a analizar. Se encuentra en el archivo ground_truth.csv.
|  id_ventana |  clasificacion_esperada |
|---|---|
|  V-ATK-01	 |  ALTO |
| V-ADM-01  |   MEDIO|
|  V-NRM-01 |  BAJO |
|  V-NRM-02 |  BAJO |
|  V-NRM-03 |  BAJO |

### Características de la Máquina Virtual y configuración
La VM consiste en un servidor emulado en *Oracle VirtualBox* corriendo *Ubuntu Server* con 2048 MB de RAM, una CPU de 2 núcleos virtuales y un disco de 20 GB. Utiliza el framework de auditoría nativo del kernel (`auditd`) mediante reglas personalizadas (`custom.rules`) para registrar *syscalls* críticas. Un script orquestador en **Python** procesa la telemetría en ventanas de 3 minutos.

Para que el script en Python y el entorno de inferencia (LM Studio) puedan comunicarse entre el Host y la VM, es mandatorio configurar la interfaz de red de la siguiente manera:
1. Apagar la máquina virtual en VirtualBox.
2. Ir a **Configuración > Red**.
3. En el **Adaptador 1**, asegurarse de que esté habilitado y seleccionar en el menú desplegable "Conectado a:": **Adaptador Puente (Bridged Adapter)**.
4. En el campo "Nombre", seleccionar la tarjeta de red activa de tu Host (Wi-Fi o Ethernet).
5. Iniciar la VM y verificar la dirección IP asignada ejecutando `ip a`. El host físico y la máquina virtual deben pertenecer a la misma subred (por ejemplo, en el rango `192.168.0.X`).

### Hardware utilizado
Servidor local montado sobre *LM Studio* que expone una API REST local (puerto 1234) compatible con OpenAI. Realiza una descarga híbrida de capas (*offloading*) combinando la CPU con la GPU (AMD Radeon RX 570 4GB) utilizando la API gráfica **Vulkan**.

---

## Metodología y resultados
### Métricas Evaluadas
* Eficacia Analítica (Detección Semántica): Evaluada mediante la construcción de una matriz de Verdad de Campo (Ground Truth). Se contrastaron los veredictos de los LLMs frente a las etiquetas reales del dataset para medir falsos positivos y falsos negativos, analizando la capacidad de la IA para entender el contexto global en lugar de palabras aisladas.

* Costo Computacional (Latencia): Medido de forma precisa utilizando la librería time incorporada en los scripts de orquestación, cronometrando los milisegundos transcurridos desde el envío del payload HTTP POST hasta la respuesta JSON definitiva del motor de inferencia.

* Resumen de Resultados Obtenidos
Regex: Demostró ceguera semántica. Procesamiento instantáneo (milisegundos) pero con una tasa del 100% de falsos positivos en el entorno V-ADM-01 al alarmarse por la simple aparición sintáctica de comandos bloqueados.

* Modelos de Lenguaje: Demostraron comprensión contextual. Phi-3 Mini superó a Mistral en eficiencia, logrando una reducción del 23% en la latencia (162.60s frente a 212.82s en la ventana de ataque) y manteniendo una precisión forense impecable, identificando la legitimidad del SysAdmin y la peligrosidad del atacante.

---

## Limitaciones identificadas
* Frontera Física de Hardware (VRAM): La GPU Radeon RX 570 cuenta únicamente con 4 GB de VRAM. Al procesar contextos largos (ventana establecida en 9192 tokens), el framework de LM Studio se ve obligado a realizar una inferencia híbrida, descargando solo 20 capas de Mistral y 18 de Phi-3 en la GPU, derivando el resto a la CPU y generando un severo cuello de botella.

* Restricción de Tiempo Real: Debido a latencias promedio de entre 2.5 y 3.5 minutos por bloque de log, la solución es inviable para mitigación reactiva inmediata en infraestructuras de producción en vivo.

* Sesgo de Hipervigilancia: Los modelos operan en estado stock de propósito general. La falta de un Fine-Tuning específico en administración Linux provoca que actividades rutinarias densas tiendan a ser categorizadas preventivamente como riesgo ALTO.

---

## Autores y contexto académico
* Santiago Agustín Gonzalez: autor principal y desarrollador.
* Benjamín Chuquimango: coautor y director académico
* Universidad Nacional de General Sarmiento, 2026.
* Trabajo Final Individual de Sistemas Operativos y Redes 2, primer semestre de 2026.

---

## Estado y licencia
