import argparse
import nmap
import json
import os
import re
import sys
from datetime import datetime
from html import escape
from colorama import Fore, init

init(autoreset=True)

#Comprueba que el host o el ip sean formatos validos
def valid_ip(ip) -> bool:
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return True
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ip):
        return True
    return False


#Verifica si el rango de puertos esta dento del limite 1-65535
def valid_ports(ports: str) -> bool:
    """
    Valida formatos simples:
      - Rango: 20-1024
      - Lista: 22,80,443
      - Mezcla sin espacios: 22,80,8000-8100
    """
    if not ports or len(ports.strip()) == 0:
        return False

    parts = ports.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            sub = part.split("-")
            if len(sub) != 2:
                return False
            try:
                a = int(sub[0])
                b = int(sub[1])
            except ValueError:
                return False
            if not (1 <= a <= 65535 and 1 <= b <= 65535 and a <= b):
                return False
        else:
            try:
                p = int(part)
            except ValueError:
                return False
            if not (1 <= p <= 65535):
                return False
    return True

#Funcion encargada de el escaneó
def scan_target(target: str, ports: str, nm_args: str = "-sV") -> dict:
    nm = nmap.PortScanner()
    results = {
        "target": target,
        "ports_scanned": ports,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": []
    }
    
    print(Fore.CYAN + f"\n🔍 Escaneando {target} en puertos {ports}...\n")
    try:
        nm.scan(target, ports, arguments=nm_args)
    except Exception as e:
        print(Fore.RED + f"❌ Error al ejecutar nmap: {e}")
        return results

    for host in nm.all_hosts():
        hostname = nm[host].hostname() or "-"
        print(Fore.MAGENTA + f"Host: {host} ({hostname})")
        print(Fore.BLUE + f"Estado: {nm[host].state()}")
        print("-" * 40)
        for proto in nm[host].all_protocols():
            ports_list = nm[host][proto].keys()
            for port in sorted(ports_list):
                state = nm[host][proto][port].get("state", "unknown")
                service = nm[host][proto][port].get("name", "Desconocido")
                version = nm[host][proto][port].get("version", "")
                print(Fore.GREEN + f"Puerto {port}/{proto} -> {state} ({service} {version})")
                results["results"].append({
                    "port": port,
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "version": version
                })

    print(Fore.CYAN + "\n✅ Escaneo completado.\n")
    return results

#Función para crear un nombre de archivo que no genere conflictos
def safe_filename_for_target(target: str) -> str:
    return target.replace(".", "_").replace(":", "_").replace("/", "_")

#Función para guardar el resultado en un json
def save_results_to_json(results: dict, filename: str):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(Fore.YELLOW + f"💾 Resultados guardados en {filename}")
    except Exception as e:
        print(Fore.RED + f"❌ Error al guardar JSON: {e}")

#Generador del HTML y CSS
def build_report_html(results: dict, json_filename: str) -> str:
    target = results.get("target", "desconocido")
    ports_scanned = results.get("ports_scanned", "")
    timestamp = results.get("timestamp", datetime.now().isoformat())
    rows = results.get("results", [])

    # Contar por estado
    counts = {}
    for r in rows:
        state = r.get("state", "unknown")
        counts[state] = counts.get(state, 0) + 1
    states = list(counts.keys())
    values = [counts[s] for s in states]

    # Construir filas HTML
    table_rows = ""
    for r in rows:
        port = r.get("port", "")
        proto = escape(str(r.get("protocol", "")))
        state = escape(str(r.get("state", "")))
        service = escape(str(r.get("service", "")))
        version = escape(str(r.get("version", "")))
        table_rows += f"<tr><td>{port}</td><td>{proto}</td><td>{state}</td><td>{service}</td><td>{version}</td></tr>\n"

    css = """
    body { font-family: Arial, Helvetica, sans-serif; margin: 20px; color:#222 }
    header { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; }
    h1 { margin:0; font-size:1.4rem; }
    .meta { text-align:right; font-size:0.9rem; color:#555 }
    .card { background:#fff; border-radius:8px; box-shadow:0 2px 6px rgba(0,0,0,0.08); padding:16px; margin-top:16px; }
    table { width:100%; border-collapse:collapse; margin-top:12px; }
    th, td { padding:8px 10px; border-bottom:1px solid #eee; text-align:left; }
    th { background:#f7f7f7; font-weight:600; }
    .small { font-size:0.9rem; color:#555; }
    .center { text-align:center; }
    footer { margin-top:18px; font-size:0.85rem; color:#666; }
    @media (max-width:720px){ .meta { text-align:left; margin-top:8px } }
    """

    html = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe de escaneo - {escape(target)}</title>
<style>{css}</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<header>
  <div>
    <h1>Informe de escaneo — {escape(target)}</h1>
    <div class="small">Puertos: {escape(str(ports_scanned))}</div>
  </div>
  <div class="meta">
    <div>Generado: {escape(timestamp)}</div>
    <div>Origen JSON: {escape(json_filename)}</div>
  </div>
</header>

<section class="card">
  <h2 class="small">Resumen</h2>
  <p class="small">Total puertos listados: <strong>{len(rows)}</strong></p>
  <canvas id="stateChart" style="width:100%;max-width:400px;height:180px;margin:auto;display:block"></canvas>
</section>

<section class="card">
  <h2 class="small">Detalle por puerto</h2>
  <table>
    <thead>
      <tr><th>Puerto</th><th>Protocolo</th><th>Estado</th><th>Servicio</th><th>Versión</th></tr>
    </thead>
    <tbody>
      {table_rows if table_rows else '<tr><td colspan="5" class="center">No se encontraron puertos</td></tr>'}
    </tbody>
  </table>
</section>

<footer class="card">
  <div>Generado por: <strong>Ricardo Islas</strong></div>
  <div>Proyecto: Port Scanner — resultados procesados</div>
  <div>Nota: Solo para uso autorizado.</div>
</footer>

<script>
const ctx = document.getElementById('stateChart').getContext('2d');
const chart = new Chart(ctx, {{
    type: 'bar',
    data: {{
        labels: {states},
        datasets: [{{
            label: 'Conteo por estado',
            data: {values},
            borderWidth: 1,
            backgroundColor: 'rgba(54, 162, 235, 0.6)',
            borderColor: 'rgba(54, 162, 235, 1)'
        }}]
    }},
    options: {{
        scales: {{
            y: {{
                beginAtZero: true,
                ticks: {{ precision:0 }}
            }}
        }},
        plugins: {{
            legend: {{ display: false }},
            title: {{ display: true, text: 'Estados de puertos' }}
        }}
    }}
}});
</script>

</body>
</html>
"""
    return html

#Generador del reporte en formato json
def generate_report_from_json(json_path: str, out_html: str = None) -> str:
    if not os.path.exists(json_path):
        raise FileNotFoundError(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        results = json.load(f)
    html = build_report_html(results, json_path)
    if not out_html:
        base = os.path.splitext(os.path.basename(json_path))[0]
        out_html = f"report_{base}.html"
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)
    return out_html

#Argumentos para la CLI
def parse_args():
    parser = argparse.ArgumentParser(description="Port scanner unificado (interactive + CLI).")
    parser.add_argument("--target", "-t", help="IP o dominio a escanear")
    parser.add_argument("--ports", "-p", help="Rango/lista de puertos (ej. 20-1024 o 22,80,443)")
    parser.add_argument("--save", "-s", action="store_true", help="Guardar resultados en JSON")
    parser.add_argument("--out", "-o", help="Nombre de archivo JSON de salida")
    parser.add_argument("--report", "-r", action="store_true", help="Generar informe HTML a partir del JSON (si --save)")
    parser.add_argument("--args", help="Argumentos extra para nmap (por defecto: -sV)", default="-sV")
    return parser.parse_args()

#Flujo de trabajo interactivo.
def interactive_flow():
    print(Fore.YELLOW + "=== Escáner de Puertos (modo interactivo) ===")
    while True:
        target = input("Introduce la dirección IP o dominio a escanear (o 'q' para salir): ").strip()
        if target.lower() in ("q", "exit"):
            print("Saliendo.")
            sys.exit(0)
        if not valid_ip(target):
            print(Fore.RED + "Formato de IP/host inválido. Intenta de nuevo.")
            continue
        ports = input("Introduce el rango/lista de puertos (ej. 20-1024 o 22,80,443): ").strip()
        if not valid_ports(ports):
            print(Fore.RED + "Formato de puertos inválido. Intenta de nuevo.")
            continue

        results = scan_target(target, ports, nm_args="-sV")
        save_opt = input("¿Deseas guardar los resultados en JSON? (s/n): ").lower()
        if save_opt == "s":
            filename = f"scan_results_{safe_filename_for_target(target)}.json"
            save_results_to_json(results, filename)
            print(f"Puedes generar un informe HTML con:\n  python {os.path.basename(__file__)} --report --out {filename}")
        cont = input("¿Deseas escanear otro objetivo? (s/n): ").lower()
        if cont != "s":
            break

def main():
    args = parse_args()
    # Si no hay argumentos, se inicia el modo interactivo
    if not args.target or not args.ports or not args.out:
        interactive_flow()
        return

    target = args.target
    ports = args.ports
    nm_args = args.args

    # Validaciones
    if not valid_ip(target):
        print(Fore.RED + "Formato de IP/host inválido. Salida.")
        sys.exit(1)
    if not valid_ports(ports):
        print(Fore.RED + "Formato de puertos inválido. Salida.")
        sys.exit(1)

    results = scan_target(target, ports, nm_args)

    out_json = args.out
    if args.save:
        if not out_json:
            out_json = f"scan_results_{safe_filename_for_target(target)}.json"
        if os.path.exists(out_json):
            print(Fore.YELLOW + f"Advertencia: {out_json} ya existe y se sobrescribirá.")
        save_results_to_json(results, out_json)

    if args.report:
        # En caso de solicitar solo el reporte sin usas el comando --save o -s, buscara un json existente para generar el HTML
        json_path = out_json if args.save else None
        if not json_path:
            print(Fore.YELLOW + "No se especificó --save. Buscando JSON existente...")
            # El script usara el formato que crea por defecto para buscar un json existente
            candidate = f"scan_results_{safe_filename_for_target(target)}.json"
            if os.path.exists(candidate):
                json_path = candidate
            else:
                print(Fore.RED + "No se encontró JSON para generar el informe. Use --save para guardar primero.")
                return
        try:
            out_html = generate_report_from_json(json_path)
            print(Fore.GREEN + f"✅ Informe generado: {out_html}")
        except Exception as e:
            print(Fore.RED + f"Error generando informe: {e}")
            
if __name__ == "__main__":
    main()
