#!/usr/bin/env python3
"""
Network Test Server with TCP/UDP Support

A production-ready test server that supports:
- TCP mode (with optional SSL/TLS)
- UDP mode (with UDP file transfer)
- Variable file size via --size flag
- Variable test duration via --duration flag
- Concurrent client handling via threading

Usage:
    python test_server.py --protocol tcp --size 10 --duration 3600
    python test_server.py --protocol udp --size 5 --duration 1800
"""

import socket
import ssl
import threading
import os
import time
import struct
import argparse
from datetime import datetime
from typing import Optional, Dict, Tuple


# =============================================================================
# Constants
# =============================================================================

UDP_DATA_MAGIC = 0x55445046  # "UDPF" in hex
UDP_PAYLOAD_SIZE = 1400      # Bytes per UDP packet
UDP_MAX_RETRIES = 5
UDP_PACKET_HEADER_SIZE = 20  # 5 x 4-byte fields


class NetworkTestServer:
    """
    Production-ready test server supporting TCP and UDP protocols.

    Features:
    - Protocol selection (TCP or UDP) via flag
    - Variable file size generation
    - Variable test duration
    - Thread-safe file size changes
    - Concurrent client support
    - Comprehensive statistics tracking
    """

    def __init__(
        self,
        host: str = '0.0.0.0',
        port: int = 8443,
        protocol: str = 'tcp',
        file_size_mb: int = 10,
        max_connections: int = 50,
        enable_ssl: bool = False
    ):
        """
        Initialize the test server.

        Args:
            host: Host address to bind (default: 0.0.0.0)
            port: Port number for TCP/UDP (default: 8443)
            protocol: 'tcp' or 'udp' (default: 'tcp')
            file_size_mb: Initial test file size in MB (default: 10)
            max_connections: Maximum concurrent connections (default: 50)
            enable_ssl: Enable SSL/TLS for TCP mode (default: True)
        """
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.max_connections = max_connections
        self.enable_ssl = enable_ssl and self.protocol == 'tcp'

        # Validate protocol
        if self.protocol not in ('tcp', 'udp'):
            raise ValueError(f"Invalid protocol: {protocol}. Use 'tcp' or 'udp'")

        # Thread-safe file size management
        self._file_size_mb = file_size_mb
        self._file_size_lock = threading.Lock()
        self._test_data: bytes = b''

        # Generate test data
        self._regenerate_test_data()

        # Statistics (thread-safe)
        self.stats: Dict = {
            'total_connections': 0,
            'successful_transfers': 0,
            'failed_transfers': 0,
            'total_bytes_sent': 0,
            'udp_requests': 0,
            'udp_errors': 0,
        }
        self._stats_lock = threading.Lock()

        # Server state
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._threads: list = []

        # UDP retransmission cache (address -> (data, total_chunks, timestamp))
        self._udp_cache: Dict[Tuple, Tuple[bytes, int, float]] = {}
        self._udp_cache_lock = threading.Lock()
        self._udp_cache_ttl = 120  # seconds

    @property
    def file_size_mb(self) -> int:
        """Thread-safe getter for file size."""
        with self._file_size_lock:
            return self._file_size_mb

    @file_size_mb.setter
    def file_size_mb(self, value: int):
        """Thread-safe setter for file size with data regeneration."""
        with self._file_size_lock:
            self._file_size_mb = value
            self._regenerate_test_data()
            print(f"[INFO] File size changed to {value}MB ({len(self._test_data):,} bytes)")

    def _regenerate_test_data(self):
        """Generate deterministic test data of configured size."""
        pattern = b"NETWORK_TEST_DATA_PATTERN_" * 100
        size_bytes = self._file_size_mb * 1024 * 1024
        repetitions = (size_bytes // len(pattern)) + 1
        self._test_data = (pattern * repetitions)[:size_bytes]

    def _get_test_data_snapshot(self) -> bytes:
        """Get a thread-safe snapshot of test data."""
        with self._file_size_lock:
            return self._test_data

    # =========================================================================
    # TCP Mode Implementation
    # =========================================================================

    def _start_tcp_server(self):
        """Start TCP server socket."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(self.max_connections)
        self._server_socket.settimeout(1.0)

        proto = "TCP" + ("+SSL" if self.enable_ssl else "")
        print(f"[OK] {proto} server listening on {self.host}:{self.port}")

    def _handle_tcp_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle individual TCP client connection."""
        with self._stats_lock:
            self.stats['total_connections'] += 1
            conn_num = self.stats['total_connections']

        start_time = time.time()
        data_sent = 0
        success = False

        try:
            # SSL wrap if enabled
            if self.enable_ssl:
                ssl_context = self._create_ssl_context()
                client_socket = ssl_context.wrap_socket(
                    client_socket,
                    server_side=True,
                    suppress_ragged_eofs=True
                )

            # Read HTTP request
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')

            if not request or not request.startswith('GET'):
                return

            # Build and send HTTP response with test data
            test_data = self._get_test_data_snapshot()
            response_headers = (
                "HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(test_data)}\r\n"
                f"Content-Disposition: attachment; filename=test_{self.file_size_mb}MB.bin\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            client_socket.sendall(response_headers.encode())
            client_socket.sendall(test_data)

            data_sent = len(test_data)
            success = True

        except Exception as e:
            with self._stats_lock:
                self.stats['failed_transfers'] += 1
            print(f"[TCP #{conn_num}] Error from {address[0]}: {e}")

        finally:
            # Update statistics
            with self._stats_lock:
                if success:
                    self.stats['successful_transfers'] += 1
                self.stats['total_bytes_sent'] += data_sent

            # Log completion
            duration = time.time() - start_time
            speed_mbps = (data_sent * 8) / (duration * 1_000_000) if duration > 0 else 0
            print(
                f"[TCP #{conn_num}] {address[0]} - "
                f"{data_sent / (1024*1024):.1f}MB in {duration:.2f}s ({speed_mbps:.2f} Mbps)"
            )

            # Cleanup
            try:
                client_socket.close()
            except:
                pass

    def _accept_tcp_connections(self):
        """Main TCP connection acceptor loop."""
        while self._running:
            try:
                client_socket, address = self._server_socket.accept()
                thread = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client_socket, address),
                    daemon=True
                )
                thread.start()
                self._threads.append(thread)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"[TCP] Accept error: {e}")

    # =========================================================================
    # UDP Mode Implementation
    # =========================================================================

    def _start_udp_server(self):
        """Start UDP server socket."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.settimeout(1.0)
        print(f"[OK] UDP server listening on {self.host}:{self.port}")

    def _handle_udp_request(self, data: bytes, address: Tuple[str, int]):
        """Handle UDP requests for file transfer."""
        with self._stats_lock:
            self.stats['udp_requests'] += 1

        try:
            # Check for GETF (Get File) binary request
            if data[:4] == b'GETF':
                self._send_file_udp(address)
                return

            # Handle text commands
            message = data.decode('utf-8', errors='ignore').strip()

            if message == 'PING':
                self._send_udp_response(address, b'PONG')
            elif message == 'GET_SIZE':
                self._send_udp_response(address, f"SIZE:{self.file_size_mb}".encode())
            elif message.startswith('SET_SIZE:'):
                try:
                    new_size = int(message.split(':')[1])
                    if 1 <= new_size <= 1000:  # 1MB to 1GB
                        self.file_size_mb = new_size
                        self._send_udp_response(address, f"OK:{new_size}".encode())
                    else:
                        self._send_udp_response(address, b"ERROR:Size must be 1-1000 MB")
                except (ValueError, IndexError):
                    self._send_udp_response(address, b"ERROR:Invalid size format")
            elif message.startswith('GET_MISSING:'):
                seq_str = message.split(':', 1)[1]
                self._resend_missing_chunks(address, seq_str)
            else:
                self._send_udp_response(address, b"ERROR:Unknown command")

        except Exception as e:
            with self._stats_lock:
                self.stats['udp_errors'] += 1
            print(f"[UDP] Error handling {address}: {e}")

    def _send_udp_response(self, address: Tuple[str, int], data: bytes):
        """Send UDP response to client."""
        try:
            self._server_socket.sendto(data, address)
        except Exception as e:
            print(f"[UDP] Failed to send response to {address}: {e}")

    def _build_udp_packet(self, data: bytes, seq: int, total_chunks: int) -> bytes:
        """
        Build UDP packet with header.

        Header format (20 bytes):
        - Magic (4 bytes): 0x55445046
        - Sequence (4 bytes): packet index
        - Total chunks (4 bytes): total packets
        - Chunk size (4 bytes): payload size
        - Total size (4 bytes): full file size
        """
        total_size = len(data)
        start = seq * UDP_PAYLOAD_SIZE
        end = min(start + UDP_PAYLOAD_SIZE, total_size)
        chunk = data[start:end]

        header = struct.pack(
            '!IIIII',
            UDP_DATA_MAGIC,
            seq,
            total_chunks,
            len(chunk),
            total_size
        )

        return header + chunk

    def _send_file_udp(self, address: Tuple[str, int]):
        """Send complete file over UDP with packet retransmission support."""
        test_data = self._get_test_data_snapshot()
        total_size = len(test_data)
        total_chunks = (total_size + UDP_PAYLOAD_SIZE - 1) // UDP_PAYLOAD_SIZE

        # Cache for potential retransmission requests
        with self._udp_cache_lock:
            self._udp_cache[address] = (test_data, total_chunks, time.time())

        print(f"[UDP] Sending {total_size / (1024*1024):.1f}MB to {address} ({total_chunks} packets)")

        # Send all chunks sequentially
        packets_sent = 0
        for seq in range(total_chunks):
            packet = self._build_udp_packet(test_data, seq, total_chunks)
            self._server_socket.sendto(packet, address)
            packets_sent += 1

        with self._stats_lock:
            self.stats['successful_transfers'] += 1
            self.stats['total_bytes_sent'] += total_size

        print(f"[UDP] Transfer complete to {address} ({packets_sent} packets)")

    def _resend_missing_chunks(self, address: Tuple[str, int], seq_str: str):
        """Resend specific chunks requested by client."""
        # Parse requested sequences
        sequences = []
        for s in seq_str.split(','):
            s = s.strip()
            if s.isdigit():
                sequences.append(int(s))

        if not sequences:
            return

        # Get cached data or generate fresh
        with self._udp_cache_lock:
            cache_entry = self._udp_cache.get(address)

        if cache_entry and time.time() - cache_entry[2] < self._udp_cache_ttl:
            test_data, total_chunks, _ = cache_entry
        else:
            test_data = self._get_test_data_snapshot()
            total_chunks = (len(test_data) + UDP_PAYLOAD_SIZE - 1) // UDP_PAYLOAD_SIZE

        # Resend requested chunks
        packets_sent = 0
        for seq in sequences:
            if 0 <= seq < total_chunks:
                packet = self._build_udp_packet(test_data, seq, total_chunks)
                self._server_socket.sendto(packet, address)
                packets_sent += 1

        print(f"[UDP] Resent {packets_sent}/{len(sequences)} chunks to {address}")

    def _process_udp_requests(self):
        """Main UDP request processing loop."""
        while self._running:
            try:
                data, address = self._server_socket.recvfrom(4096)
                self._handle_udp_request(data, address)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"[UDP] Error: {e}")

        # Cleanup old cache entries
        with self._udp_cache_lock:
            self._udp_cache.clear()

    # =========================================================================
    # SSL/TLS Support (TCP Mode Only)
    # =========================================================================

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with certificate."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        cert_file = 'server.crt'
        key_file = 'server.key'

        # Generate certificates if missing
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            print("[SSL] Generating self-signed certificates...")
            self._generate_certificates(cert_file, key_file)

        context.load_cert_chain(cert_file, key_file)
        return context

    def _generate_certificates(self, cert_file: str, key_file: str):
        """Generate self-signed SSL certificate."""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import datetime as dt

            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Network Test Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                dt.datetime.utcnow()
            ).not_valid_after(
                dt.datetime.utcnow() + dt.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())

            # Write files
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            print(f"[SSL] Generated: {cert_file}, {key_file}")

        except ImportError:
            print("[ERROR] cryptography library required for SSL")
            print("Install: pip install cryptography")
            raise

    # =========================================================================
    # Server Lifecycle
    # =========================================================================

    def start(self, duration: Optional[int] = None):
        """
        Start the test server.

        Args:
            duration: Optional duration in seconds. Server stops automatically.
                     If None, runs until Ctrl+C.
        """
        print("=" * 70)
        print("NETWORK TEST SERVER")
        print("=" * 70)
        print(f"Protocol:    {self.protocol.upper()}{' + SSL' if self.enable_ssl else ''}")
        print(f"Host:        {self.host}")
        print(f"Port:        {self.port}")
        print(f"File Size:   {self.file_size_mb} MB")
        print(f"Max Clients: {self.max_connections}")
        if duration:
            print(f"Duration:    {duration} seconds")
        else:
            print("Duration:    Unlimited (Ctrl+C to stop)")
        print("=" * 70)
        print()

        self._running = True
        start_time = time.time()

        # Start appropriate server type
        if self.protocol == 'tcp':
            self._start_tcp_server()
            server_func = self._accept_tcp_connections
        else:
            self._start_udp_server()
            server_func = self._process_udp_requests

        try:
            if duration:
                # Run for specified duration
                print("[SERVER] Running for", duration, "seconds...")
                end_time = time.time() + duration
                while self._running and time.time() < end_time:
                    server_func()
                print(f"\n[SERVER] Duration ({duration}s) complete")
            else:
                # Run until interrupted
                while self._running:
                    server_func()

        except KeyboardInterrupt:
            print("\n[SERVER] Shutdown requested")
        finally:
            self._running = False

            # Wait for threads to finish
            for thread in self._threads:
                thread.join(timeout=2)

            # Close server socket
            if self._server_socket:
                try:
                    self._server_socket.close()
                except:
                    pass

            # Print statistics
            self._print_statistics()

    def stop(self):
        """Stop the server gracefully."""
        self._running = False

    def _print_statistics(self):
        """Print final server statistics."""
        print()
        print("=" * 70)
        print("SERVER STATISTICS")
        print("=" * 70)

        if self.protocol == 'tcp':
            print(f"Total Connections:    {self.stats['total_connections']}")
            print(f"Successful Transfers: {self.stats['successful_transfers']}")
            print(f"Failed Transfers:     {self.stats['failed_transfers']}")
        else:
            print(f"UDP Requests:         {self.stats['udp_requests']}")
            print(f"Successful Transfers: {self.stats['successful_transfers']}")
            print(f"UDP Errors:           {self.stats['udp_errors']}")

        print(f"Total Data Sent:      {self.stats['total_bytes_sent'] / (1024**3):.2f} GB")

        if self.stats['total_connections'] > 0 or self.stats['udp_requests'] > 0:
            total = self.stats['total_connections'] or self.stats['udp_requests']
            success_rate = (self.stats['successful_transfers'] / total) * 100
            print(f"Success Rate:         {success_rate:.1f}%")

        print("=" * 70)


# =============================================================================
# Command Line Interface
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Network Test Server with TCP/UDP Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # TCP server with SSL, 10MB file, unlimited duration
  python test_server.py --protocol tcp --size 10

  # UDP server, 5MB file, 1 hour duration
  python test_server.py --protocol udp --size 5 --duration 3600

  # TCP server without SSL, custom port
  python test_server.py --protocol tcp --no-ssl --port 8080

  # UDP server on specific interface
  python test_server.py --protocol udp --host 192.168.1.100 --port 9000
        """
    )

    parser.add_argument(
        '--protocol',
        type=str,
        default='tcp',
        choices=['tcp', 'udp'],
        help='Protocol mode: tcp or udp (default: tcp)'
    )

    parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Host address to bind (default: 0.0.0.0)'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=8443,
        help='Port number (default: 8443)'
    )

    parser.add_argument(
        '--size',
        type=int,
        default=10,
        help='Test file size in MB (default: 10)'
    )

    parser.add_argument(
        '--duration',
        type=int,
        default=None,
        help='Server duration in seconds (default: unlimited)'
    )

    parser.add_argument(
        '--max-connections',
        type=int,
        default=50,
        help='Maximum concurrent connections (default: 50)'
    )

    parser.add_argument(
        '--no-ssl',
        action='store_true',
        help='Disable SSL/TLS for TCP mode'
    )

    args = parser.parse_args()

    # Create and start server
    server = NetworkTestServer(
        host=args.host,
        port=args.port,
        protocol=args.protocol,
        file_size_mb=args.size,
        max_connections=args.max_connections,
        enable_ssl=not args.no_ssl
    )

    server.start(duration=args.duration)


if __name__ == '__main__':
    main()
