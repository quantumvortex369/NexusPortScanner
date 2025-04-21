import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from rich.progress import track
from datetime import datetime

# Inicializar colorama para colores en Windows
init(autoreset=True)

# 🎯 Input del usuario
target = input(Fore.CYAN + "🔍 IP o dominio objetivo: ").strip()

try:
    ip = socket.gethostbyname(target)
    host = socket.gethostbyaddr(ip)[0]
except socket.gaierror:
    print(Fore.RED + "❌ No se pudo resolver el dominio.")
    exit()

print(Fore.GREEN + f"\n🎯 Escaneando: {ip} ({host})")

# 🔢 Rango de puertos
start_port = int(input(Fore.YELLOW + "⚙️ Puerto de inicio: "))
end_port = int(input(Fore.YELLOW + "⚙️ Puerto final: "))

# 📁 Archivo de salida con codificación UTF-8
output_file = f"nexus_scan_{target.replace('.', '_')}.txt"

# 🧠 Función para obtener banner del servicio
def grab_banner(sock):
    try:
        sock.send(b'HEAD / HTTP/1.1\r\n\r\n')
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner
    except:
        return None

# 🚪 Función para escanear un solo puerto
def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    s.settimeout(1)
                    banner = grab_banner(s)
                except:
                    banner = None
                banner_info = f" | Banner: {banner}" if banner else ""
                print(Fore.GREEN + f"[+] Puerto {port} ABIERTO{banner_info}")
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(f"Puerto {port} ABIERTO{banner_info}\n")
    except:
        pass

# 📝 Guardar cabecera del archivo
with open(output_file, "w", encoding="utf-8") as f:
    f.write(f"📅 Scan: {datetime.now()}\n🎯 Objetivo: {ip} ({host})\n\n")

# ⚡ Ejecutar escaneo con barra de progreso
print(Fore.CYAN + f"\n⏳ Escaneando puertos del {start_port} al {end_port}...\n")

with ThreadPoolExecutor(max_workers=100) as executor:
    for port in track(range(start_port, end_port + 1), description="📡 Escaneando"):
        executor.submit(scan_port, port)

print(Fore.MAGENTA + f"\n✅ Scan finalizado. Resultados guardados en {output_file}")
