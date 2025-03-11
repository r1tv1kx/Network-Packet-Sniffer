import scapy.all as scapy
import tkinter as tk
from tkinter import ttk, messagebox
import psutil

# Function to get user-friendly network interface names
def get_network_interfaces():
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        if any(addr.family == 2 for addr in addrs):  # IPv4 check
            if "Wi-Fi" in interface or "wlan" in interface.lower():
                interfaces.append(("Wi-Fi", interface))
            elif "Ethernet" in interface or "eth" in interface.lower():
                interfaces.append(("Ethernet", interface))
            else:
                interfaces.append((interface, interface))
    return interfaces

# Function to display packet information
def packet_info(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Insert packet details into the text box
        result_text.insert(tk.END, f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}\n")
        result_text.yview(tk.END)  # Auto-scroll to latest entry

# Function to start packet sniffing
def start_sniffing():
    selected_name = interface_var.get()
    interface = interface_dict.get(selected_name, None)

    if not interface:
        messagebox.showerror("Error", "Please select a valid network interface.")
        return

    try:
        # Sniff asynchronously with store=0 to avoid memory issues
        scapy.sniff(iface=interface, count=10, store=0, prn=lambda pkt: packet_info(pkt))
    except Exception as e:
        messagebox.showerror("Sniffing Error", str(e))

# Create GUI
root = tk.Tk()
root.title("Network Packet Sniffer")
root.geometry("900x400")  # Landscape layout

# Create frames
main_frame = tk.Frame(root, padx=10, pady=10)
main_frame.pack(fill="both", expand=True)

# Network Interface Selection
ttk.Label(main_frame, text="Select Network Interface:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=5, sticky="w")
interface_var = tk.StringVar()
interface_dict = {name: value for name, value in get_network_interfaces()}
interface_dropdown = ttk.Combobox(main_frame, textvariable=interface_var, values=list(interface_dict.keys()), state="readonly")
interface_dropdown.grid(row=0, column=1, padx=10, pady=5, sticky="w")

# Start Button
start_button = ttk.Button(main_frame, text="Start Sniffing", command=start_sniffing)
start_button.grid(row=0, column=2, padx=10, pady=5, sticky="w")

# Packet Display
ttk.Label(main_frame, text="Captured Packets:", font=("Arial", 12)).grid(row=1, column=0, columnspan=3, padx=10, pady=5, sticky="w")
result_text = tk.Text(main_frame, height=15, width=100, bg="black", fg="green")
result_text.grid(row=2, column=0, columnspan=3, padx=10, pady=5)

# Run GUI
root.mainloop()
