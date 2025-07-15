Network Packet Analyzer

A dark-themed, mecha-style GUI tool built with Python and Scapy to monitor live network traffic. Packets are displayed in real time with a sleek, neon terminal aesthetic.
🚀 Features

    🎮 Dark Mode + Mecha UI: Futuristic dark theme with glowing green visuals.

    🧠 Live Packet Sniffing: Displays real-time summaries of captured packets.

    ✅ Start & Stop: Easily control packet capture with GUI buttons.

    🧰 Threaded Sniffer: Non-blocking GUI using multithreading.

🖥️ Screenshot

<!-- Replace with an actual image filename -->
🛠️ Requirements

    Python 3.8 or higher

    Npcap (required for Scapy on Windows)

📦 Installation 

  Install Python dependencies:

    pip install scapy



  Install Npcap on Windows from https://npcap.com/#download

  🧪 Usage

    Save the following files in your project folder:

        sniffer_gui.py (main GUI script)

        packet_sniffer.py (if you modularize the sniffer logic)

    ##Run the app:
     python sniffer_gui.py

🖱️ GUI Controls

    ▶ Start Sniffing: Begins capturing packets in real time.

    ⛔ Stop Sniffing: Halts packet capture gracefully.

Captured data appears in the scrollable output window.
📁 File Structure

NPA/
├── sniffer_gui.py       # Main GUI application
├── packet_sniffer.py    # sniffer logic
└──  README.md




🧑‍💻 Built With

    Python

    Scapy

    Tkinter

⚠️ Disclaimer

    Packet sniffing may require admin privileges and must comply with local laws and network policies. Use responsibly.
