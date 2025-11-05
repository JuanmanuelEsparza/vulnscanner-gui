#!/usr/bin/env python3

import subprocess  # Para ejecutar comandos externos como Nmap
import sys  # Para manejar argumentos de línea de comandos
import os  # Para crear carpetas y archivos
import requests  # Para hacer llamadas a la API de Vulners

def run_nmap(target, report_dir):
    """Ejecuta Nmap para escanear puertos y servicios, guarda el reporte."""
    command = ["nmap", "-sV", "-O", target]  # Comando Nmap: escanea versiones de servicios y OS
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)  # Ejecuta y captura salida, con timeout de 5 min
        with open(f"{report_dir}/nmap_scan.txt", 'w') as f:  # Guarda la salida en un archivo
            f.write(result.stdout)
        return result.stdout  # Devuelve la salida para procesar
    except subprocess.TimeoutExpired:
        print("Error: Nmap tardó demasiado. Verifica la IP.")
        return ""
    except Exception as e:
        print(f"Error ejecutando Nmap: {e}")
        return ""

def search_vulners(service, version):
    """Busca vulnerabilidades en la API de Vulners usando el servicio y versión."""
    url = "https://vulners.com/api/v3/search/lucene/"  # URL de la API
    query = f"{service} {version}"  # Consulta: ej. "http Apache 2.4"
    try:
        response = requests.get(url, params={"query": query}, timeout=10)  # Llama a la API
        if response.status_code == 200:  # Si la respuesta es OK
            data = response.json()  # Convierte a JSON
            vulns = data.get("data", {}).get("search", [])  # Extrae vulnerabilidades
            return [f"ID: {v.get('id')} - CVSS: {v.get('cvss', {}).get('score', 'N/A')}" for v in vulns[:5]]  # Top 5 con ID y CVSS
        else:
            return [f"Error HTTP: {response.status_code}"]
    except requests.RequestException as e:
        return [f"Error en API: {e}"]
    return []

def main():
    if len(sys.argv) != 2:  # Verifica que se pase exactamente 1 argumento (la IP)
        print("Uso: python3 vuln_scanner.py <IP del objetivo>")
        print("Ejemplo: python3 vuln_scanner.py 192.168.1.100")
        sys.exit(1)
    
    target = sys.argv[1]  # La IP del objetivo
    report_dir = "reports"  # Carpeta para reportes
    os.makedirs(report_dir, exist_ok=True)  # Crea la carpeta si no existe
    
    print(f"Iniciando escaneo automatizado en {target} con Python...")
    
    # Paso 1: Escaneo con Nmap
    nmap_output = run_nmap(target, report_dir)
    if not nmap_output:
        print("Escaneo fallido. Saliendo.")
        sys.exit(1)
    print("Nmap completado. Reporte guardado.")
    
    # Paso 2: Parsear la salida de Nmap y buscar vulnerabilidades
    vulnerabilities = []  # Lista para almacenar resultados
    lines = nmap_output.split('\n')  # Divide la salida en líneas
    for line in lines:
        if '/tcp' in line and 'open' in line:  # Busca líneas con puertos abiertos
            parts = line.split()  # Divide la línea en palabras
            if len(parts) > 2:
                service = parts[2]  # Extrae el servicio (ej. 'http')
                version = ' '.join(parts[3:]) if len(parts) > 3 else 'unknown'  # Extrae la versión
                print(f"Buscando vulnerabilidades para {service} {version}...")
                vulns = search_vulners(service, version)  # Busca en Vulners
                if vulns:
                    vulnerabilities.append(f"Servicio: {service} {version}\nVulnerabilidades:\n" + "\n".join(vulns))
    
    # Paso 3: Generar reporte de vulnerabilidades
    with open(f"{report_dir}/vulners_report.txt", 'w') as f:
        if vulnerabilities:
            f.write("\n\n".join(vulnerabilities))  # Escribe todas las vulnerabilidades
        else:
            f.write("No se encontraron vulnerabilidades conocidas para los servicios detectados.")
    
    print("¡Escaneo completado!")
    print(f"Reportes guardados en {report_dir}:")
    print("- nmap_scan.txt: Detalles del escaneo de Nmap.")
    print("- vulners_report.txt: Vulnerabilidades encontradas.")

if __name__ == "__main__":
    main()  # Ejecuta la función principal
