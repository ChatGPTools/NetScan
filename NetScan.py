import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import json
import requests

class NetWatchApp:
    def __init__(self, master):
        self.master = master
        master.title("NetWatch - Network Security Toolkit")
        master.geometry("700x500")

        self.configurations = self.load_configurations()
        self.setup_ui()

    def load_configurations(self):
        try:
            with open('config.json', 'r') as config_file:
                return json.load(config_file)
        except FileNotFoundError:
            return {}

    def setup_ui(self):
        self.tab_control = ttk.Notebook(self.master)

        self.reputation_tab = ttk.Frame(self.tab_control)
        self.settings_tab = ttk.Frame(self.tab_control)
        self.network_monitor_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.reputation_tab, text='Reputazione')
        self.tab_control.add(self.settings_tab, text='Impostazioni')
        self.tab_control.add(self.network_monitor_tab, text='Monitoraggio Rete')

        self.setup_reputation_tab()
        self.setup_settings_tab()
        self.setup_network_monitor_tab()

        self.tab_control.pack(expand=1, fill="both")

    def setup_reputation_tab(self):
        ttk.Label(self.reputation_tab, text="Inserisci URL/IP:").pack(pady=10)
        self.url_ip_entry = ttk.Entry(self.reputation_tab)
        self.url_ip_entry.pack(pady=10)
        ttk.Button(self.reputation_tab, text="Verifica", command=self.check_reputation).pack(pady=10)
        self.reputation_results_text = tk.Text(self.reputation_tab, height=15, width=80)
        self.reputation_results_text.pack(pady=10)

    def check_reputation(self):
        url_ip = self.url_ip_entry.get()
        if not url_ip:
            messagebox.showwarning("Attenzione", "Inserisci un URL o un IP per la verifica.")
            return
    
        api_key = self.configurations.get("api_key", "")
        if not api_key:
            messagebox.showwarning("Attenzione", "Chiave API non configurata nelle impostazioni.")
            return

        headers = {"x-apikey": api_key}
        params = {"url": url_ip}  # Per indirizzi IP, VirusTotal API potrebbe richiedere parametri leggermente diversi

        try:
            response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
            if response.status_code == 200:
                report_url = response.json().get("data", {}).get("id", "")
                analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{report_url}", headers=headers)
                if analysis_response.status_code == 200:
                    result = analysis_response.json().get("data", {}).get("attributes", {}).get("stats", {})
                    self.reputation_results_text.delete(1.0, tk.END)
                    self.reputation_results_text.insert(tk.END, f"Risultati per {url_ip}:\n{result}\n")
                else:
                    messagebox.showerror("Errore", "Errore nell'ottenere il rapporto di analisi.")
            else:
                messagebox.showerror("Errore", "Errore nella richiesta di verifica.")
        except requests.RequestException as e:
            messagebox.showerror("Errore", f"Errore di rete: {e}")

    def setup_settings_tab(self):
        ttk.Label(self.settings_tab, text="Chiave API:").pack(pady=10)
        self.api_key_entry = ttk.Entry(self.settings_tab)
        self.api_key_entry.pack(pady=10)
        self.api_key_entry.insert(0, self.configurations.get("api_key", ""))
        ttk.Button(self.settings_tab, text="Salva Impostazioni", command=self.save_settings).pack(pady=10)

    def save_settings(self):
        self.configurations["api_key"] = self.api_key_entry.get()
        with open('config.json', 'w') as config_file:
            json.dump(self.configurations, config_file)
        messagebox.showinfo("Impostazioni", "Impostazioni salvate con successo.")

    def setup_network_monitor_tab(self):
        ttk.Label(self.network_monitor_tab, text="Dispositivi Rilevati sulla Rete:").pack(pady=20)
        self.network_devices_text = tk.Text(self.network_monitor_tab, height=15, width=80)
        self.network_devices_text.pack(pady=10)
        ttk.Button(self.network_monitor_tab, text="Scansiona Rete", command=self.scan_network).pack(pady=10)

    def scan_network(self):
        # Simulazione di una scansione di rete
        fake_devices = [":^)"]
        self.network_devices_text.delete(1.0, tk.END)
        self.network_devices_text.insert(tk.END, "\n".join(fake_devices))

if __name__ == "__main__":
    root = tk.Tk()
    app = NetWatchApp(root)
    root.mainloop()
