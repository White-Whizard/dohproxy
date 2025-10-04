import unittest
import socket
from dohproxy import doh_query, load_config

class TestDoHProxy(unittest.TestCase):
    def setUp(self):
        self.config = load_config('config.yaml')
        self.doh_url = self.config['doh_url']
        self.timeout = self.config['timeout']
        self.proxy_host = self.config['listen_host']
        self.proxy_udp_port = self.config['udp_port']
        self.proxy_tcp_port = self.config['tcp_port']
        # Example DNS query for 'example.com' (A record)
        # This is a raw DNS query in wire format for testing
        self.dns_query = bytes.fromhex(
            'abcd01000001000000000000076578616d706c6503636f6d0000010001'
        )

    def test_doh_query_success(self):
        response = doh_query(self.dns_query, self.doh_url, self.timeout)
        self.assertIsInstance(response, bytes)
        self.assertGreater(len(response), 0)
        # Check that the response has the same transaction ID
        self.assertEqual(response[:2], self.dns_query[:2])
        
    def test_udp_proxy(self):
        """Test that the UDP proxy is working by sending a query directly to it."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Send query to proxy
            sock.sendto(self.dns_query, (self.proxy_host, self.proxy_udp_port))
            
            # Receive response
            response, _ = sock.recvfrom(4096)
            
            # Verify response
            self.assertIsInstance(response, bytes)
            self.assertGreater(len(response), 0)
            self.assertEqual(response[:2], self.dns_query[:2])  # Check transaction ID matches
            
        finally:
            sock.close()

if __name__ == "__main__":
    unittest.main()
