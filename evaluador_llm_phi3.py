import os
import re
import csv
import requests
import time
# =====================================
#configuración del entorno
# =====================================
HOST_IP = "192.168.0.6" #mi ip local del host windows
LM_STUDIO_URL = f"http://{HOST_IP}:1234/v1/chat/completions" #endpoint de la api

#Definimos las palabras clave cobre las reglas para eliminar el ruido secundario del sistemas
MIS_KEYS_VALIDAS = ["passwd_changes", "shadow_changes", "sudoers_changes", "exec_commands", "root_commands"]

# ====================================
# 1- Función de pre-filtrado
# ====================================
# aca vamos a filtrar el contenido del DataSet para extraer unicamente las lineas relacionadas a las reglas de adutd definidas

def pre_filtrar_log (ruta_archivo):
	#leemos el archivo ausearch crudo y lo filtramos
	lineas_interesantes = []

	if not os.path.exists(ruta_archivo):
		print (f"[-] ERROR: no se encontró el archivo {ruta_archivo}")
		return ""

	with open(ruta_archivo, "r") as f:
		for linea in f:
			#comprobamos si la linea contiene alguna de nuestras claves
			if any(f'key="{k}"' in linea for k in MIS_KEYS_VALIDAS):
				# limpieza menor de espacios y saltos de linea redundantes
				lineas_interesantes.append(linea.strip())
		#retornamos el bloque consolidado de logs filtrados
	# CONTROL DE CONTEXTO: Si hay demasiadas líneas, tomamos solo las últimas 30
	# para evitar saturar los tokens (n_ctx) del LM Studio
	if len(lineas_interesantes) > 30:
		lineas_interesantes = lineas_interesantes[-30:]
	return "\n".join(lineas_interesantes)

# ==============================================
# 2- Diseño del prompt con Chain-of-Thought
# ==============================================
def armar_prompt(id_ventana, logs_filtrados):
	#Construimos un prompt estructurado de ciberseguridad forense, obligando al modelo a deducir la cronologia
	#paso a paso antes de entregar la etuqieta del riesgo
	prompt = f"""Eres un analista experto en seguridad de sistemas operativos Linux y auditoría forense mediante el subsistema auditd. Analiza las siguiente ventana temporal de eventos de auditoría pre-filtrados correspondientes al ID {id_ventana}

Reglas de Negocio/Contexto técnico del entorno
- key="exec_commands": Registra ejecuciones mediante la syscall execve. Actividad común en modo usuario, pero sospechosa si se encadena de forma anidada con escaladas.
- key "sudoers_changes": Registra modificaiones o intentos sobre los privilegios de sudo. Si registra "success=no", representa una denegación de accesos críticos.
- key="shadow_changes" / "passwd_changes": Registra accesos o modificaciones sobre las bases de datos de credenciales del sistema operativo.

Instrucciones de análisis (Chain-of_Thought):
1. Examina la cronología de los eventos proporcionados en los logs.
2. Identifica si las acciones aisladas (que individualmente pueden ser de riesgo BAJO o MEDIO) forman una secuencia de ataque coordinado dentro del bloque de tiempo.
3. Determina el veredicto final basándote estrictamente en una de las siguientes tres categorías:
	- BAJO: Actividad rutinaria, consultas válidas, comandos interactivos estándar sin elevación sospechosa.
	- MEDIO: Errores administrativos aislados, modificaciones por root legítimo de forma directa y limpia sin alertas denegadas previas.
	- ALTO: Secuencias multi-paso sospechosas (ej. reconocimiento -> denegación de permisos -> escalada/modificación exitosa de archivos de credenciales.

LOGS PRE_FILTRADOS A ANIALIZAR:
{logs_filtrados}

Responde estrictamente cumpliendo con el siguiente formato JSON de un solo nivel (PROHIBIDO crear listas, arrays o sub-objetos dentro del razonamiento, escribe todo en un solo párrafo de texto plano):
{{
	"Razonamiento": "Escribe aquí un único párrafo continuo de texto plano con el análisis cronológico resumido",
	"Riesgo": "BAJO, MEDIO o ALTO"
}}
"""
	return prompt

# ========================================
# 3- Llamada a la api de LM estudio
# ========================================
# Realizamos la petición POST al servidor local de LM Studio emulando el formato OpenAI.
# Como restricción metodológica mantenemos la temperatua a 0.2
def consultar_llm(prompt):
	payload = {
		"model": "phi-3.1-mini-128k-instruct",
		"messages": [
			{
			"role": "user",
			"content": f"INSTRUCCIÓN DE SISTEMA: Eres un sistema automatizado de clasificación de seguridad que analiza logs forenses de Linux y responde ESTRICTAMENTE en formato JSON.\n\n{prompt}"
			}
		],
		"temperature": 0.2
	}

	try:
		response = requests.post(LM_STUDIO_URL, json=payload, timeout=None)
		if response.status_code == 200:
			# Decodificamos el JSON de la respuesta general de la API
			datos_api = response.json()
			# Extraemos el contenido interno del mensaje de forma nativa como dicta el estándar
			contenido_modelo = datos_api["choices"][0]["message"]["content"]
			return contenido_modelo
		else:
			return f"ERROR API: código de estado {response.status_code} | Detalle: {response.text}"

	except requests.exceptions.RequestException as e:
		return f"ERROR de conexión: No se pudo contectar a LM Studio {LM_STUDIO_URL}. Detalle {e}"

# ===========================================
#4- LOOP principal de ejecución automatizado
# ===========================================
def ejecutar_pipeline():
	print ("[*] Iniciando Pipeline de Clasificación de Auditoría Inteligente...")
	print (f"[*] Conectando con Host de Inferencia: {LM_STUDIO_URL}\n")

	ruta_csv = "ground_truth.csv"
	if not os.path.exists(ruta_csv):
		print(f"[-] ERROR fatal: No se encuentra el archivo indexador {ruta_csv}")
		return
	carpeta_salida = "outputs"
	if not os.path.exists(carpeta_salida):
		os.makedirs(carpeta_salida)
	#Leemos las ventanas registradas en el CSV
	with open(ruta_csv, mode="r") as csv_file:
		reader = csv.DictReader(csv_file)

		for fila in reader:
			id_ventana = fila["id_ventana"].strip()
			verdad_esperada = fila["clasificacion_esperada"].strip()

			archivo_log = f"{id_ventana}.txt"
			print(f"[+] Procesando bloque: {archivo_log} | Ground Truth: {verdad_esperada}")

			#Paso A: limpiamos los logs crudos
			logs_limpios = pre_filtrar_log(archivo_log)

			if not logs_limpios:
				print(f"   [-] Ventana vacía o sin claves. saltando consulta.\n")
				continue

			#Paso B: construimos el prompt con la data inyectada
			prompt_final = armar_prompt(id_ventana, logs_limpios)

			#Paso C: Enviamos a LM Studio
			print(f"    [*] Enviando payload a la GPU del Host (Temperatura: 0.2)...")

			#INICIAMOS EL CRONÓMETRO AUTOMÁTICO
			tiempo_inicio = time.time()
			respuesta_modelo = consultar_llm(prompt_final)
			#DETENEMOS EL CRONÓMETRO
			tiempo_fin = time.time()
			segundos_totales = tiempo_fin - tiempo_inicio
			# Formateamos el tiempo en Minutos y Segundos para que sea fácil de leer
			minutos = int(segundos_totales // 60)
			segundos_restantes = segundos_totales % 60

			respuesta_modelo = consultar_llm(prompt_final)

			print (f"   [=] RESPUESTA DEL MODELO:\n{respuesta_modelo}")
			#IMPRIMIMOS LA MÉTRICA DE TIEMPO
			print(f"Tiempo de procesamiento: {minutos} min {segundos_restantes:.2f} s ({segundos_totales:.2f} segundos totales)")
			print ("-" * 80 + "\n")

			# === EXPORTACIÓN A ARCHIVO DE TEXTO INDIVIDUAL ===
			# Creamos el nombre de archivo dinámico basado en el ID de la ventana analizada
			nombre_archivo_salida = f"{id_ventana}_resultado_phi3.json"
			ruta_completa_salida = os.path.join(carpeta_salida, nombre_archivo_salida)
			
			with open(ruta_completa_salida, mode="w", encoding="utf-8") as f_out:
				# Guardamos la respuesta en texto plano (que contiene la estructura JSON de la IA)
				f_out.write(respuesta_modelo.strip())
			
			print(f"    [+] Resultado analítico guardado con éxito en: {ruta_completa_salida}")

if __name__ == "__main__":
	ejecutar_pipeline()
