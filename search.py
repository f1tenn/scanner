import tkinter as tk
from tkinter import ttk
import scapy.all as scapy
import nmap

# path to manuf
scapy.conf.manufdb = "here"

class Scanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner")
        self.root.geometry("500x300")

        # Create tabs
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True)

        # Create scan tab
        self.scan_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.scan_tab, text="Scan")

        # Create report tab
        self.report_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.report_tab, text="Report")

        # Create scan frame
        self.scan_frame = ttk.Frame(self.scan_tab)
        self.scan_frame.pack(fill="both", expand=True)

        # Create IP address label and entry
        self.ip_label = ttk.Label(self.scan_frame, text="IP Address:")
        self.ip_label.pack()
        self.ip_entry = ttk.Entry(self.scan_frame, width=20)
        self.ip_entry.pack()

        # Create port range label and entry
        self.port_label = ttk.Label(self.scan_frame, text="Port Range:")
        self.port_label.pack()
        self.port_entry = ttk.Entry(self.scan_frame, width=20)
        self.port_entry.pack()

        # Create scan button
        self.scan_button = ttk.Button(self.scan_frame, text="Scan", command=self.scan_network)
        self.scan_button.pack()

        # Create report frame
        self.report_frame = ttk.Frame(self.report_tab)
        self.report_frame.pack(fill="both", expand=True)

        # Create report text box
        self.report_text = tk.Text(self.report_frame, width=50, height=10)
        self.report_text.pack()

    def scan_network(self):
        # Get IP address and port range from entries
        ip_address = self.ip_entry.get()
        port_range = self.port_entry.get()

        # Scan network 
        scanner = IPScanner(ip_address, port_range)
        scanner.scan()

        # Get scan results
        results = scanner.get_results()

        # Generate report
        report = ""
        for result in results:
            report += f"IP Address: {result['ip']}\n"
            report += f"Open Ports: {result['ports']}\n"
            report += f"Vulnerabilities: {result['vulnerabilities']}\n\n"

        # Display report in text box
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(tk.END, report)

class IPScanner:
    def __init__(self, ip_address, port_range):
        self.ip_address = ip_address
        self.port_range = port_range
        self.results = []

    def scan(self):
        # Scan network using Scapy
        scapy_packet = scapy.IP(dst=self.ip_address)
        scapy_packet = scapy_packet/scapy.TCP(dport=self.port_range)
        scapy_response = scapy.sr(scapy_packet, timeout=1, verbose=0)

        # Get open ports and vulnerabilities using Nmap
        nmap_scan = nmap.PortScanner()
        nmap_scan.scan(self.ip_address, self.port_range)

        # Process scan results
        for host in scapy_response:
            for port in host[1]:
                if port.status() == "open":
                    self.results.append({
                        "ip": host[0].dst,
                        "ports": port.dport,
                        "vulnerabilities": self.get_vulnerabilities(nmap_scan, host[0].dst, port.dport)
                    })

    def get_results(self):
        return self.results

    def get_vulnerabilities(self, nmap_scan, ip_address, port):
        # Using Nmap
        vulnerabilities = []
        for vuln in nmap_scan[ip_address].tcp(port)["scripts"]:
            vulnerabilities.append(vuln["id"])
        return vulnerabilities

if __name__ == "__main__":
    root = tk.Tk()
    app = Scanner(root)
    root.mainloop()