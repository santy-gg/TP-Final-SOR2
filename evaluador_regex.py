import os
import re
import csv
import time

# DEFINICIÓN DE REGLAS TRADICIONALES (Firmas de expresiones regulares)
# Simulamos un motor SIEM clásico: si detecta ciertas llaves o comandos de root, eleva el riesgo.
REGEX_ALTO = re.compile(r'(shadow_changes|passwd_changes|sudoers_changes)')
REGEX_MEDIO = re.compile(r'(exec_commands|root_commands)')

def clasificar_con_regex(ruta_archivo):
    if not os.path.exists(ruta_archivo):
        return "ERROR", "Archivo no encontrado"

    lineas_interesantes = []
    with open(ruta_archivo, "r") as f:
        for linea in f:
            if any(k in linea for k in ["passwd_changes", "shadow_changes", "sudoers_changes", "exec_commands", "root_commands"]):
                lineas_interesantes.append(linea.strip())

    # Mantenemos las mismas 30 líneas por consistencia metodológica
    if len(lineas_interesantes) > 30:
        lineas_interesantes = lineas_interesantes[-30:]

    texto_bloque = "\n".join(lineas_interesantes)

    # Lógica de clasificación por Firmas (Plana, sin Chain-of-Thought)
    if REGEX_ALTO.search(texto_bloque):
        return "ALTO", "Alerta: Se detectaron modificaciones directas en archivos críticos de credenciales o sudoers."
    elif REGEX_MEDIO.search(texto_bloque):
        return "MEDIO", "Aviso: Se detectaron ejecuciones de comandos de sistema o intentos de elevación."
    else:
        return "BAJO", "Actividad normal: No se encontraron patrones de firmas de riesgo."

def ejecutar_pipeline_regex():
    print("[*] Iniciando Clasificador Tradicional basado en Expresiones Regulares (Regex)... \n")
    ruta_csv = "ground_truth.csv"

    with open(ruta_csv, mode="r") as csv_file:
        reader = csv.DictReader(csv_file)
        for fila in reader:
            id_ventana = fila["id_ventana"].strip()
            verdad_esperada = fila["clasificacion_esperada"].strip()
            archivo_log = f"{id_ventana}.txt"

            print(f"[+] Procesando bloque: {archivo_log} | Ground Truth: {verdad_esperada}")

            # CRONÓMETRO AUTOMÁTICO PARA REGEX
            tiempo_inicio = time.time()

            riesgo_predicho, razon = clasificar_con_regex(archivo_log)

            tiempo_fin = time.time()
            segundos_totales = tiempo_fin - tiempo_inicio

            print(f"   [=] RESPUESTA REGEX:")
            print(f"       \"Razonamiento\": \"{razon}\"")
            print(f"       \"Riesgo\": \"{riesgo_predicho}\"")
            print(f"   [ Tiempo de procesamiento: {segundos_totales * 1000:.4f} milisegundos ({segundos_totales:.6f} segundos totales)")
            print("-" * 80 + "\n")

if __name__ == "__main__":
    ejecutar_pipeline_regex()
