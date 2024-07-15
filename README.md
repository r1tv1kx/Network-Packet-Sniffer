# Network-Packet-Sniffer
This Python script utilizes the scapy library to capture and analyze network packets on a specified network interface. It prompts the user to input the interface name and captures a specified number of packets, displaying relevant information such as source IP, destination IP, protocol, and packet payload.

1 Features:
- Flexible Interface Selection: Allows users to specify the network interface (Ethernet, Wi-Fi, etc.) from which packets should be captured.
- Packet Information Display: Extracts and prints important details from each captured packet, including source and destination IP addresses, protocol type, and raw payload data.
- Error Handling: Includes error handling to manage potential issues when attempting to capture packets, providing informative error messages when problems occur.

2 Requirements:
- Python 3.x
- scapy library (pip install scapy)

3 Usage:
- Clone or download the script.
- Install the scapy library if not already installed (pip install scapy).
- Run the script and follow the prompt to enter the network interface name.
- View the displayed packet information, including IP addresses, protocol details, and packet payload.

4 Note:
- Ensure you have appropriate permissions to capture network packets on the specified interface.
- Use responsibly and adhere to legal and ethical guidelines when capturing and analyzing network data.
