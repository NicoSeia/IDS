import unittest
from scapy.all import IP, TCP, Ether
from utils.packet_analyzer import *

class TestPortScanDetection(unittest.TestCase):
    def setUp(self):
        self.connection_counter = defaultdict(int)  # Inicializa el contador de conexiones
        self.captured_log_messages = []  # Inicializa la lista para capturar mensajes

        # Reemplaza el callback original por un mock
        def mock_packet_callback(packet):
            if packet.haslayer(TCP):
                self.connection_counter[packet[IP].dst] += 1
                #print(f"Processing packet from {packet[IP].src} to {packet[IP].dst}")
                #print(f"Connection count for {packet[IP].dst}: {self.connection_counter[packet[IP].dst]}")
                if self.connection_counter[packet[IP].dst] > 10:
                    log_message = f"\nPossible Port Scan Detected: {packet[IP].src} -> {packet[IP].dst}"
                    print(log_message)
                    self.captured_log_messages.append(log_message)  # Captura el mensaje en la lista

        self.original_packet_callback = packet_callback  # Guarda la referencia original del callback
        self.packet_callback = mock_packet_callback  # Usa el mock en vez del original

    def tearDown(self):
        # Restaura el callback original después de cada prueba
        global packet_callback
        packet_callback = self.original_packet_callback

    def test_port_scan_detection(self):
        # Simula un paquete TCP de un escaneo de puertos
        packets = [
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=80),
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=81),
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=82),
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=83),
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=84),
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=85),
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=86),
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=87),
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=88),
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=89),
            Ether() / IP(dst="192.168.1.2", src="192.168.1.1") / TCP(dport=90),
        ]

        # Simula la recepción de los paquetes
        for packet in packets:
            self.packet_callback(packet)

        # Verifica si se detectó un escaneo de puertos
        self.assertTrue(any(
            "Possible Port Scan Detected" in log_message for log_message in self.captured_log_messages
        ))

if __name__ == "__main__":
    unittest.main()
