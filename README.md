# 🔍 Port Scanner — Python + Nmap

Herramienta educativa desarrollada en **Python** para realizar escaneos de puertos en equipos locales o remotos.  
Permite descubrir servicios, versiones y generar **informes JSON y HTML visuales** con estadísticas.

> ⚠️ **Uso educativo y ético:** Este proyecto está destinado al aprendizaje y pruebas controladas en redes propias o autorizadas.

---

## 🧠 Objetivos del proyecto

- Practicar automatización y scripting en Python.
- Aplicar fundamentos de **redes y ciberseguridad**.
- Aprender a usar la librería `python-nmap`.
- Desarrollar y presentar resultados en formatos profesionales (JSON y HTML).
- Mostrar buenas prácticas de desarrollo (validación, CLI, documentación, automatización).

---

## ⚙️ Requisitos

- Python **3.8 o superior**
- [Nmap instalado en tu sistema](https://nmap.org/download.html)
- Librerías adicionales (instalar con `pip install -r requirements.txt`)

---

## 1. Uso Básico

Ejcuta el programa sin darle argumentos y sigue las instrucciones en pantalla.

**Ejemplo:**
python scanner.py
=== Escáner de Puertos (modo interactivo) ===

Introduce la dirección IP o dominio a escanear: 192.168.1.34

Introduce el rango/lista de puertos (ej. 20-1024 o 22,80,443): 20-1024

¿Deseas guardar los resultados en JSON? (s/n): s

💾 Resultados guardados en scan_results_192_168_1_34.json

Puedes generar un informe HTML con:

  python scanner.py --report --out scan_results_192_168_1_34.json

---

## 2. Modo no interactivo (CLI)
Escaneo directo con argumentos:

**Escaneo y guardado JSON**

python scanner.py --target 192.168.1.34 --ports 22,80,443 --save

**Escaneo, guardado y generación de informe HTML**

python scanner.py -t 192.168.1.34 -p 20-1024 -s -r

**Si ya tienes un JSON previo, puedes solo generar el informe**

python scanner.py --report --out scan_results_192_168_1_34.json

---

## Conocimientos aplicados

* Python intermedio (CLI, validación, JSON, HTML).
* Uso de librerías: nmap, argparse, colorama.
* Conceptos básicos de ciberseguridad y redes TCP/IP.
* Buenas prácticas de documentación y legibilidad.
* Automatización y exportación de resultados.

---

## ⚠ Ética y responsabilidad

El escaneo de puertos puede revelar información sensible.
Usa este programa solo en entornos donde tengas autorización.
El autor no se hace responsable por el uso indebido de esta herramienta.

Desarrolado con apoyo y guia de ChatGPT
