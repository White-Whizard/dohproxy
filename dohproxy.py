import socket
import threading
import requests
import logging
import yaml
import sys
import time
import dns.message
import struct

from typing import Tuple, Dict, Any, Optional

# Load configuration
def load_config(path: str) -> dict:
    with open(path, 'r') as f:
        return yaml.safe_load(f)

# DNS over HTTPS client
def parse_dns_query(dns_query: bytes) -> Dict[str, Any]:
    """Extract information from a DNS query for logging purposes"""
    try:
        msg = dns.message.from_wire(dns_query)
        info = {
            'id': msg.id,
            'questions': []
        }
        for question in msg.question:
            q_info = {
                'name': str(question.name),
                'type': dns.rdatatype.to_text(question.rdtype),
                'class': dns.rdataclass.to_text(question.rdclass)
            }
            info['questions'].append(q_info)
        return info
    except Exception as e:
        logging.debug(f"Failed to parse DNS query: {e}")
        return {'id': None, 'questions': []}

def parse_dns_response(dns_response: bytes) -> Dict[str, Any]:
    """Extract information from a DNS response for logging purposes"""
    try:
        msg = dns.message.from_wire(dns_response)
        info = {
            'id': msg.id,
            'rcode': dns.rcode.to_text(msg.rcode()),
            'answer_count': len(msg.answer),
            'authority_count': len(msg.authority),
            'additional_count': len(msg.additional),
            'answers': []
        }
        
        # Extract IP addresses and other record data from answers
        for rrset in msg.answer:
            for rr in rrset:
                answer_info = {
                    'name': str(rrset.name),
                    'type': dns.rdatatype.to_text(rrset.rdtype),
                    'ttl': rrset.ttl,
                    'data': str(rr)
                }
                
                # Special handling for common record types
                if rrset.rdtype == dns.rdatatype.A or rrset.rdtype == dns.rdatatype.AAAA:
                    answer_info['ip'] = str(rr)
                elif rrset.rdtype == dns.rdatatype.MX:
                    answer_info['preference'] = rr.preference
                    answer_info['exchange'] = str(rr.exchange)
                elif rrset.rdtype == dns.rdatatype.CNAME:
                    answer_info['cname'] = str(rr.target)
                
                info['answers'].append(answer_info)
        
        return info
    except Exception as e:
        logging.debug(f"Failed to parse DNS response: {e}")
        return {'id': None, 'rcode': None, 'answer_count': 0, 'answers': []}

def format_response_for_log(dns_response: bytes) -> str:
    """Format DNS response data for logging, specifically extracting IP addresses"""
    try:
        import dns.message
        import dns.rdatatype
        import dns.rdata
        
        msg = dns.message.from_wire(dns_response)
        result = []
        
        for rrset in msg.answer:
            for rr in rrset:
                if rrset.rdtype == dns.rdatatype.A or rrset.rdtype == dns.rdatatype.AAAA:
                    result.append(f"{str(rr)} (TTL: {rrset.ttl})")
                elif rrset.rdtype == dns.rdatatype.CNAME:
                    result.append(f"CNAME: {str(rr.target)} (TTL: {rrset.ttl})")
                elif rrset.rdtype == dns.rdatatype.MX:
                    result.append(f"MX: {rr.preference} {str(rr.exchange)} (TTL: {rrset.ttl})")
                else:
                    result.append(f"{dns.rdatatype.to_text(rrset.rdtype)}: {str(rr)} (TTL: {rrset.ttl})")
        
        if result:
            return " → " + ", ".join(result)
        return ""
    except Exception as e:
        logging.error(f"Error formatting response for log: {e}", exc_info=True)
        return ""

def doh_query(dns_query: bytes, doh_url: str, timeout: float) -> bytes:
    headers = {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message'
    }
    
    query_info = parse_dns_query(dns_query)
    log_prefix = ""
    if query_info['id'] is not None:
        q_names = [q['name'] for q in query_info['questions']]
        q_types = [q['type'] for q in query_info['questions']]
        log_prefix = f"[DNS:{query_info['id']}] {','.join(q_names)} {','.join(q_types)}"
        logging.info(f"{log_prefix} - Sending query to DoH server {doh_url}")
    
    start_time = time.time()
    response = requests.post(doh_url, data=dns_query, headers=headers, timeout=timeout)
    response.raise_for_status()
    elapsed = time.time() - start_time
    
    resp_data = response.content
    resp_info = parse_dns_response(resp_data)
    
    if log_prefix:
        # Format response details including IP addresses
        response_details = format_response_for_log(resp_data)
        
        # Log complete response information
        log_msg = f"{log_prefix} - Got response: {resp_info['rcode']}, answers: {resp_info['answer_count']}, elapsed: {elapsed:.3f}s{response_details}"
        logging.info(log_msg)
    
    return resp_data

# UDP DNS Proxy
class UDPProxy(threading.Thread):
    def __init__(self, listen_addr: Tuple[str, int], doh_url: str, timeout: float):
        super().__init__()
        self.listen_addr = listen_addr
        self.doh_url = doh_url
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.listen_addr)
        self.running = True
        self.stats = {
            'queries': 0,
            'errors': 0,
            'bytes_in': 0,
            'bytes_out': 0
        }
        logging.info(f"UDP proxy listening on {self.listen_addr[0]}:{self.listen_addr[1]}")

    def run(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.stats['queries'] += 1
                self.stats['bytes_in'] += len(data)
                
                query_info = parse_dns_query(data)
                client_info = f"{addr[0]}:{addr[1]}"
                
                if query_info['id'] is not None:
                    q_types = [q['type'] for q in query_info['questions']]
                    q_names = [q['name'] for q in query_info['questions']]
                    logging.info(f"UDP query from {client_info}: ID {query_info['id']} {','.join(q_names)} {','.join(q_types)}")
                else:
                    logging.info(f"UDP query from {client_info}: {len(data)} bytes")
                
                start_time = time.time()
                response = doh_query(data, self.doh_url, self.timeout)
                elapsed = time.time() - start_time
                
                # Get response details with IP addresses
                response_details = format_response_for_log(response)
                
                self.stats['bytes_out'] += len(response)
                self.sock.sendto(response, addr)
                
                logging.info(f"UDP response to {client_info}: {len(response)} bytes in {elapsed:.3f}s{response_details}")
                
                # Log stats every 100 queries
                if self.stats['queries'] % 100 == 0:
                    logging.info(f"UDP stats: queries={self.stats['queries']}, "
                                f"errors={self.stats['errors']}, "
                                f"bytes_in={self.stats['bytes_in']}, "
                                f"bytes_out={self.stats['bytes_out']}")
                    
            except Exception as e:
                self.stats['errors'] += 1
                logging.error(f"UDP error: {e}", exc_info=True)

# TCP DNS Proxy
class TCPProxy(threading.Thread):
    def __init__(self, listen_addr: Tuple[str, int], doh_url: str, timeout: float):
        super().__init__()
        self.listen_addr = listen_addr
        self.doh_url = doh_url
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(self.listen_addr)
        self.sock.listen(5)
        self.running = True
        self.stats = {
            'connections': 0,
            'queries': 0,
            'errors': 0,
            'bytes_in': 0,
            'bytes_out': 0
        }
        logging.info(f"TCP proxy listening on {self.listen_addr[0]}:{self.listen_addr[1]}")

    def run(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
                self.stats['connections'] += 1
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(conn, addr),
                    name=f"TCPClient-{addr[0]}:{addr[1]}"
                )
                client_thread.daemon = True
                client_thread.start()
                
                # Log stats every 100 connections
                if self.stats['connections'] % 100 == 0:
                    logging.info(f"TCP stats: connections={self.stats['connections']}, "
                                f"queries={self.stats['queries']}, "
                                f"errors={self.stats['errors']}, "
                                f"bytes_in={self.stats['bytes_in']}, "
                                f"bytes_out={self.stats['bytes_out']}")
            except Exception as e:
                self.stats['errors'] += 1
                logging.error(f"TCP accept error: {e}", exc_info=True)

    def handle_client(self, conn, addr):
        client_info = f"{addr[0]}:{addr[1]}"
        logging.debug(f"TCP connection from {client_info}")
        try:
            conn.settimeout(self.timeout)
            
            while self.running:
                # First 2 bytes are the length
                length_bytes = conn.recv(2)
                if not length_bytes or len(length_bytes) < 2:
                    logging.debug(f"TCP connection closed by {client_info}")
                    break
                
                length = struct.unpack("!H", length_bytes)[0]
                if length == 0:
                    logging.warning(f"TCP zero-length message from {client_info}")
                    continue
                
                # Receive the full message
                data = bytearray()
                bytes_remaining = length
                while bytes_remaining > 0:
                    chunk = conn.recv(min(bytes_remaining, 4096))
                    if not chunk:
                        break
                    data.extend(chunk)
                    bytes_remaining -= len(chunk)
                
                if bytes_remaining > 0:
                    logging.warning(f"TCP incomplete message from {client_info}, missing {bytes_remaining} bytes")
                    break
                
                self.stats['queries'] += 1
                self.stats['bytes_in'] += len(data)
                
                query_info = parse_dns_query(bytes(data))
                if query_info['id'] is not None:
                    q_types = [q['type'] for q in query_info['questions']]
                    q_names = [q['name'] for q in query_info['questions']]
                    logging.info(f"TCP query from {client_info}: ID {query_info['id']} {','.join(q_names)} {','.join(q_types)}")
                else:
                    logging.info(f"TCP query from {client_info}: {len(data)} bytes")
                
                start_time = time.time()
                response = doh_query(bytes(data), self.doh_url, self.timeout)
                elapsed = time.time() - start_time
                
                # Get response details with IP addresses
                response_details = format_response_for_log(response)
                
                # Send the response with a 2-byte length prefix
                response_length = struct.pack("!H", len(response))
                conn.sendall(response_length + response)
                
                self.stats['bytes_out'] += len(response)
                logging.info(f"TCP response to {client_info}: {len(response)} bytes in {elapsed:.3f}s{response_details}")
                
        except socket.timeout:
            logging.debug(f"TCP connection timed out for {client_info}")
        except ConnectionResetError:
            logging.debug(f"TCP connection reset by {client_info}")
        except Exception as e:
            self.stats['errors'] += 1
            logging.error(f"TCP client error for {client_info}: {e}", exc_info=True)
        finally:
            try:
                conn.close()
            except:
                pass

class DoHProxyServer:
    def __init__(self, config_path='config.yaml'):
        self.config = load_config(config_path)
        self.configure_logging()
        self.udp_proxy = None
        self.tcp_proxy = None

    def configure_logging(self):
        log_level = getattr(logging, self.config.get('log_level', 'INFO'))
        log_format = self.config.get('log_format', 
                                    '%(asctime)s %(levelname)s [%(threadName)s] %(message)s')
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.StreamHandler()
            ]
        )
        
        # Add file logging if configured
        log_file = self.config.get('log_file')
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter(log_format))
            logging.getLogger().addHandler(file_handler)
            
        # Log startup information
        logging.info(f"DoH Proxy Server starting with DoH server: {self.config['doh_url']}")
        logging.info(f"Log level set to {self.config.get('log_level', 'INFO')}")

    def start(self):
        """Start the UDP and TCP proxies"""
        self.udp_proxy = UDPProxy(
            (self.config['listen_host'], self.config['udp_port']), 
            self.config['doh_url'], 
            self.config['timeout']
        )
        self.tcp_proxy = TCPProxy(
            (self.config['listen_host'], self.config['tcp_port']), 
            self.config['doh_url'], 
            self.config['timeout']
        )
        
        self.udp_proxy.daemon = True
        self.tcp_proxy.daemon = True
        
        self.udp_proxy.start()
        self.tcp_proxy.start()
        
        logging.info("DoH Proxy Server started successfully")
        
        try:
            # Keep the main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Shutting down DoH Proxy Server...")
        finally:
            self.stop()

    def stop(self):
        """Stop the UDP and TCP proxies"""
        if self.udp_proxy:
            self.udp_proxy.running = False
            logging.info("UDP proxy stopped")
        
        if self.tcp_proxy:
            self.tcp_proxy.running = False
            logging.info("TCP proxy stopped")
            
        logging.info("DoH Proxy Server shutdown complete")

if __name__ == "__main__":
    server = DoHProxyServer()
    server.start()
