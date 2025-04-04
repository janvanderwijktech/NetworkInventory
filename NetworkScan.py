import configparser
import sqlite3
import ipaddress
import subprocess
import re
import socket
import requests
import threading
import time
import tkinter as tk
from tkinter import ttk
import winsound
import csv, tempfile, os

def load_config(config_file="settings.ini"):
    """Lees de configuratie vanuit settings.ini zonder interpolatie zodat %VAR% letterlijk wordt ingelezen."""
    config = configparser.ConfigParser(interpolation=None)
    config.read(config_file)
    return config

def init_db(db_file):
    """Initialiseer de database en maak de benodigde tabel aan."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            ip_address TEXT PRIMARY KEY,
            hostname TEXT,
            mac_vendor TEXT
        )
    ''')
    conn.commit()
    return conn

def is_online(ip):
    """Controleert of een IP-adres online is via een enkele ping."""
    try:
        result = subprocess.run(["ping", "-n", "1", "-w", "1000", ip],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"Fout bij pingen van {ip}: {e}")
        return False

def get_hostname(ip):
    """Probeer de hostnaam te achterhalen aan de hand van het IP-adres."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = ""
    return hostname

def get_mac_from_ip(ip):
    """Haal het MAC-adres op uit de ARP-tabel voor een gegeven IP-adres."""
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        pattern = r'([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})'
        for line in result.stdout.splitlines():
            if ip in line:
                match = re.search(pattern, line)
                if match:
                    return match.group(0)
    except Exception as e:
        print(f"Fout bij ophalen MAC-adres voor {ip}: {e}")
    return None

def lookup_mac_vendor(mac):
    """Zoek de fabrikant op via de macvendors API."""
    if not mac:
        return "Unknown"
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except Exception as e:
        print(f"Fout bij opzoeken van MAC vendor voor {mac}: {e}")
    return "Unknown"

def scan_network(subnet, db_conn, progress_callback=None, commands_config=None):
    """
    Voer een netwerkscan uit en sla nieuwe apparaten op in de database.
    Alleen apparaten die online zijn of eerder online waren, worden getoond.
    
    progress_callback: een functie die wordt aangeroepen met (current, total)
    commands_config: een dict met commandoregel(s) die uitgevoerd moeten worden bij nieuw ontdekte hosts.
    """
    devices = []
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(network.hosts())
    total = len(hosts)
    counter = 0
    cursor = db_conn.cursor()
    
    for ip in hosts:
        counter += 1
        if progress_callback:
            progress_callback(counter, total)
        ip_str = str(ip)
        online = is_online(ip_str)
        
        if online:
            hostname = get_hostname(ip_str)
            mac = get_mac_from_ip(ip_str)
            mac_vendor = lookup_mac_vendor(mac)
            
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_str,))
            # Als het apparaat nog niet in de DB staat: nieuw ontdekt!
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO devices (ip_address, hostname, mac_vendor) VALUES (?, ?, ?)",
                    (ip_str, hostname, mac_vendor)
                )
                db_conn.commit()
                # Voer commando's uit indien er een commands-sectie is
                if commands_config:
                    for key in commands_config:
                        command = commands_config.get(key, "").strip()
                        if command:  # Alleen als er iets in de regel staat
                            # Vervang de variabelen in het commando
                            command_executed = command.replace("%IP%", ip_str)\
                                                      .replace("%MAC%", mac if mac else "")\
                                                      .replace("%HOST%", hostname)
                            try:
                                subprocess.run(command_executed, shell=True)
                            except Exception as e:
                                print(f"Fout bij uitvoeren van commando {key}: {e}")
            devices.append({
                "ip": ip_str,
                "hostname": hostname,
                "mac_vendor": mac_vendor,
                "online": True
            })
        else:
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_str,))
            row = cursor.fetchone()
            if row:
                devices.append({
                    "ip": row[0],
                    "hostname": row[1],
                    "mac_vendor": row[2],
                    "online": False
                })
    return devices

class NetworkScannerApp(tk.Tk):
    """
    Tkinter-applicatie voor de grafische weergave van de scanresultaten.
    De bestaande data uit de database wordt meteen getoond.
    Vervolgens wordt periodiek gescand en de GUI live geüpdatet.
    Er wordt een statusbalk getoond met een countdown en een voortgangspercentage tijdens het scannen.
    Tevens kan de gebruiker met een toggle-knop notificatiegeluiden aan- of uitzetten.
    Daarnaast is er een knop om de data naar een CSV-bestand te exporteren en te openen.
    """
    def __init__(self, db_conn, config_data):
        super().__init__()
        self.db_conn = db_conn
        self.config_data = config_data
        
        self.title("Network Scanner")
        self.geometry("700x480")
        self.devices = []
        
        try:
            self.scan_interval = int(self.config_data['schedule']['scan interval in seconds'])
        except:
            self.scan_interval = 60
        
        # Lees het pad naar de notificatie wav uit de sound-sectie (indien aanwezig)
        self.sound_file = self.config_data['sound'].get('notification', None)
        # BooleanVar voor het aan/uitschakelen van geluid
        self.sound_enabled = tk.BooleanVar(value=True)
        
        self.setup_controls()
        self.setup_treeview()
        self.setup_status_bar()
        
        self.load_initial_data()
        self.after(1000, self.start_scan_thread)
    
    def setup_controls(self):
        """Voeg een controlepaneel toe met knoppen voor handmatige scan, export en sound toggle."""
        control_frame = tk.Frame(self)
        control_frame.pack(side="top", fill="x", pady=5)
        
        scan_button = tk.Button(control_frame, text="Manual Scan", command=self.manual_scan_thread)
        scan_button.pack(side="left", padx=10)
        
        export_button = tk.Button(control_frame, text="Export CSV", command=self.export_to_csv)
        export_button.pack(side="left", padx=10)
        
        sound_check = tk.Checkbutton(control_frame, text="Notification Sound",
                                     variable=self.sound_enabled)
        sound_check.pack(side="left", padx=10)
    
    def setup_treeview(self):
        """Stelt een Treeview in met kolommen die versleepbaar zijn."""
        container = tk.Frame(self)
        container.pack(fill=tk.BOTH, expand=True)
        
        columns = ("ip", "hostname", "mac_vendor", "status")
        self.tree = ttk.Treeview(container, columns=columns, show="headings")
        
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("mac_vendor", text="MAC Vendor")
        self.tree.heading("status", text="Status")
        
        self.tree.column("ip", width=120, anchor="w", stretch=True)
        self.tree.column("hostname", width=180, anchor="w", stretch=True)
        self.tree.column("mac_vendor", width=180, anchor="w", stretch=True)
        self.tree.column("status", width=60, anchor="center", stretch=False)
        
        vsb = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        
        self.tree.tag_configure("online", foreground="green")
        self.tree.tag_configure("offline", foreground="red")
    
    def setup_status_bar(self):
        """Voegt een statusbalk toe onderaan de applicatie."""
        self.status_label = tk.Label(self, text="Idle", bd=1, relief=tk.SUNKEN, anchor="w")
        self.status_label.pack(side="bottom", fill="x")
    
    def set_status(self, message):
        """Update de tekst in de statusbalk."""
        self.status_label.config(text=message)
    
    def load_initial_data(self):
        """Laad de gegevens uit de database en toon deze in de Treeview."""
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT ip_address, hostname, mac_vendor FROM devices")
        rows = cursor.fetchall()
        devices = []
        for row in rows:
            devices.append({
                "ip": row[0],
                "hostname": row[1],
                "mac_vendor": row[2],
                "online": False
            })
        self.devices = devices
        self.update_display()
    
    def start_scan_thread(self):
        """Start een achtergrondthread die periodiek de netwerkscan uitvoert."""
        thread = threading.Thread(target=self.scan_and_update, daemon=True)
        thread.start()
    
    def scan_and_update(self):
        """Voer periodiek de scan uit, werk de GUI bij en toon een countdown met voortgang."""
        db_file = self.config_data['database']['databasefile']
        thread_db_conn = sqlite3.connect(db_file)
        subnet = self.config_data['network']['subnet']
        # Haal de commands-sectie op, indien aanwezig
        commands_config = self.config_data["commands"] if "commands" in self.config_data else None
        
        while True:
            def progress_callback(current, total):
                percent = (current / total) * 100
                self.after(0, lambda: self.set_status(f"Scanning network... {percent:.0f}%"))
            
            self.devices = scan_network(subnet, thread_db_conn, progress_callback, commands_config)
            self.after(0, self.update_display)
            self.after(0, self.play_notification_sound)
            
            countdown = self.scan_interval
            while countdown > 0:
                hours, remainder = divmod(countdown, 3600)
                minutes, seconds = divmod(remainder, 60)
                time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                self.after(0, lambda t=time_str: self.set_status(f"Scan voltooid. Volgende scan over: {t}"))
                time.sleep(1)
                countdown -= 1
    
    def manual_scan_thread(self):
        """Start een thread voor een handmatige scan zodat de GUI niet blokkeert."""
        thread = threading.Thread(target=self.manual_scan, daemon=True)
        thread.start()
    
    def manual_scan(self):
        """Voer een handmatige scan uit en update de GUI."""
        db_file = self.config_data['database']['databasefile']
        thread_db_conn = sqlite3.connect(db_file)
        subnet = self.config_data['network']['subnet']
        self.after(0, lambda: self.set_status("Manual scan gestart..."))
        def progress_callback(current, total):
            percent = (current / total) * 100
            self.after(0, lambda: self.set_status(f"Manual scan... {percent:.0f}%"))
        commands_config = self.config_data["commands"] if "commands" in self.config_data else None
        self.devices = scan_network(subnet, thread_db_conn, progress_callback, commands_config)
        self.after(0, self.update_display)
        self.after(0, lambda: self.set_status("Manual scan voltooid."))
        self.after(0, self.play_notification_sound)
    
    def play_notification_sound(self):
        """Speel het notificatiegeluid als dit is ingeschakeld."""
        if self.sound_file and self.sound_enabled.get():
            try:
                winsound.PlaySound(self.sound_file, winsound.SND_FILENAME | winsound.SND_ASYNC)
            except Exception as e:
                print(f"Fout bij afspelen geluid: {e}")
    
    def update_display(self):
        """Leeg de Treeview en vul deze opnieuw met de scanresultaten."""
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        
        for device in self.devices:
            status_bullet = "●"
            tag = "online" if device["online"] else "offline"
            self.tree.insert(
                "", "end",
                values=(
                    device["ip"],
                    device["hostname"],
                    device["mac_vendor"],
                    status_bullet
                ),
                tags=(tag,)
            )
    
    def export_to_csv(self):
        """Exporteer de data uit de huidige Treeview naar een tijdelijke CSV en open deze."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.csv', mode='w', newline='', encoding='utf-8') as temp_file:
            writer = csv.writer(temp_file)
            writer.writerow(["IP Address", "Hostname", "MAC Vendor", "Status"])
            for device in self.devices:
                status = "Online" if device["online"] else "Offline"
                writer.writerow([device["ip"], device["hostname"], device["mac_vendor"], status])
            temp_filename = temp_file.name
        try:
            os.startfile(temp_filename)
        except Exception as e:
            print(f"Fout bij openen van het bestand: {e}")

def main():
    config_data = load_config("settings.ini")
    db_file = config_data['database']['databasefile']
    
    db_conn = init_db(db_file)
    app = NetworkScannerApp(db_conn, config_data)
    app.mainloop()

if __name__ == "__main__":
    main()
