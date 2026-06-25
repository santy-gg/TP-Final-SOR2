# Eficacia y Costo Computacional de LLMs en Auditoría Interna de Linux

Este repositorio contiene el código fuente, la configuración del entorno y la matriz de datos lógicos utilizados para el Trabajo Final de la materia **Sistemas Operativos y Redes 2 (Primer Semestre 2026)** de la Licenciatura en Sistemas en la **Universidad Nacional de General Sarmiento (UNGS)**.

El proyecto evalúa y contrasta la eficacia analítica (comprensión semántica) y el costo computacional (latencia) de dos Modelos de Lenguaje Extensos (LLMs) ejecutados de forma local (**Mistral 7B** y **Phi-3 Mini**) frente a un clasificador tradicional basado en **Expresiones Regulares (Regex)** para la detección de amenazas multi-paso en sistemas Linux.

---

## Arquitectura General

La solución adopta un enfoque de *Edge Computing* y aislamiento forense dividido en dos componentes principales:
1. **Entorno Víctima (Máquina Virtual):** Un servidor emulado en *Oracle VirtualBox* corriendo *Ubuntu Server*. Utiliza el framework de auditoría nativo del kernel (`auditd`) mediante reglas personalizadas (`custom.rules`) para registrar *syscalls* críticas. Un script orquestador en **Python** procesa la telemetría en ventanas de 3 minutos.
2. **Entorno de Inferencia (Host Físico):** Servidor local montado sobre *LM Studio* que expone una API REST local (puerto 1234) compatible con OpenAI. Realiza una descarga híbrida de capas (*offloading*) combinando la CPU con la GPU (AMD Radeon RX 570 4GB) utilizando la API gráfica **Vulkan**.

---

## Estructura del Repositorio

* `src/`
    * `evaluador_llm_mistral.py`/`evaluador_llm_phi3.py`: Script principal en Python que lee los registros de auditoría, estructura el prompt del sistema bajo un esquema estricto de respuesta JSON y despacha las peticiones HTTP por API.
    * `clasificador_regex.py`: Módulo de control estático lineal que evalúa sintácticamente las cadenas de texto del log utilizando expresiones regulares tradicionales.
* `config/`
    * `custom.rules`: Archivo con las directivas inyectadas en `/etc/audit/rules.d/` para vigilar la manipulación de `/etc/shadow`, `/etc/sudoers` y llamadas `execve` con privilegios de root.
* `datasets/`
    * `V-ATK-01.txt`: Telemetría cruda simulando una intrusión coordinada multi-paso (escalada de privilegios).
    * `V-ADM-01.txt`: Registros de mantenimiento administrativo legítimo de alta densidad (control de falsos positivos).
    * `V-NRM-01.txt`: Logs de ruido cotidiano y actividad rutinaria del sistema operativo.

---

## Requisitos Previos

* **Python 3.10+** (Librerías estándar: `requests`, `time`, `json`, `re`).
* **LM Studio** configurado con los siguientes modelos en formato `.gguf`:
    * `Mistral-7B-Instruct-v0.3.Q4_K_M.gguf`
    * `Phi-3-mini-4k-instruct-q4.gguf`
* Servidor de inferencia de LM Studio activo en `http://localhost:1234`.

---

## 🛠️ Instalación y Uso

1. **Clonar el repositorio:**
   ```bash
   git clone [https://github.com/santy-gg/TP-Final-SOR2.git](https://github.com/santy-gg/TP-Final-SOR2.git)
   cd TP-Final-SOR2

2. **Ejecutar el pipeline automatizado:**
   Para procesar las ventanas lógicas y enviar las solicitudes al motor de IA local, ejecutá el pipeline por cada modelo de LLM:
   `python src/evaluador_llm.py`
   `python src/evaluador_llm_mistral.py`
   `python src/evaluador_llm_phi3.py`
   
3. **Ejecutar la línea base (Regex):**
   Para comparar los resultados semánticos con la lógica de control tradicional: `python src/clasificador_regex.py`

---
**Parámetros de Inferencia de los LLMs**
Para garantizar la estabilidad del experimento y la homogeneidad de los resultados, los modelos en LM Studio deben configurarse bajo los siguientes parámetros estrictos:
- **Temperature:** 0.2 (Penalización de la creatividad para mitigar alucinaciones forenses).
- **Context Length:** 9192 tokens (Permite la ingesta completa de la densidad de logs).
- **GPU Offload:** 20 capas para Mistral 7B y 18 capas para Phi-3 Mini (Límite condicionado por restricciones físicas de 4 GB de VRAM).

---

**Créditos e Institución**
- **Alumno:** Santiago Agustín Gonzalez
- **Legajo:** 42841155
- **Docente:** Benjamín Chuquimango
- **Institución:** Universidad Nacional de General Sarmiento (UNGS) - Instituto de Industria
- **Año:** 2026
   
