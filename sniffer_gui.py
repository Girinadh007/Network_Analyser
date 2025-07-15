import tkinter as tk
from tkinter import ttk
import threading
from scapy.all import sniff
import queue

class PacketSniffer:
    def __init__(self, output_callback):
        self.output_callback = output_callback
        self.sniff_thread = None
        self.stop_sniff_event = threading.Event()

    def start_sniffing(self):
        if self.sniff_thread is None or not self.sniff_thread.is_alive():
            self.stop_sniff_event.clear()
            self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
            self.sniff_thread.start()

    def stop_sniffing(self):
        self.stop_sniff_event.set()

    def _sniff_packets(self):
        sniff(prn=self.process_packet, store=0, stop_filter=lambda _: self.stop_sniff_event.is_set())

    def process_packet(self, packet):
        self.output_callback(packet.summary())

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.configure(bg="#121212")

        self.output_queue = queue.Queue()
        self.sniffer = PacketSniffer(self.queue_packet)

        self.setup_styles()
        self.build_widgets()

        self.update_output()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TButton",
                        foreground="#00FF88",
                        background="#222222",
                        font=("Consolas", 12, "bold"),
                        padding=6)
        style.map("TButton",
                  background=[("active", "#00FF88")],
                  foreground=[("active", "#000000")])

        style.configure("TFrame", background="#121212")
        style.configure("TLabel", background="#121212", foreground="#00FF88", font=("Consolas", 14))

    def build_widgets(self):
        frame = ttk.Frame(self.root)
        frame.pack(pady=10)

        self.start_button = ttk.Button(frame, text="▶ Start Sniffing", command=self.sniffer.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = ttk.Button(frame, text="⛔ Stop Sniffing", command=self.sniffer.stop_sniffing)
        self.stop_button.pack(side=tk.LEFT, padx=10)

        self.text_frame = ttk.Frame(self.root)
        self.text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.output_text = tk.Text(self.text_frame, bg="#1e1e1e", fg="#00ff88", insertbackground="white",
                                   font=("Courier New", 10), wrap=tk.WORD)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = ttk.Scrollbar(self.text_frame, command=self.output_text.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.output_text['yscrollcommand'] = self.scrollbar.set

    def queue_packet(self, text):
        self.output_queue.put(text)

    def update_output(self):
        try:
            while True:
                line = self.output_queue.get_nowait()
                self.output_text.insert(tk.END, line + '\n')
                self.output_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self.update_output)

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("800x500")
    app = SnifferGUI(root)
    root.mainloop()
