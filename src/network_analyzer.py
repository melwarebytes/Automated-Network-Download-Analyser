#!/usr/bin/env python3
"""
Network Download Analyzer with TCP/UDP Support

A production-ready download analyzer that supports:
- TCP mode (with optional SSL/TLS)
- UDP mode (with UDP file transfer)
- Variable file size request via --size flag
- Variable test duration via --duration flag
- Comprehensive metrics collection
- JSON result logging

Usage:
    python network_analyzer.py --protocol tcp --size 10 --duration 3600 http://server:8443/test
    python network_analyzer.py --protocol udp --size 5 --duration 1800 http://server:8443/test
"""

import socket
import ssl
import time
import json
import os
import hashlib
import struct
import threading
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse



# =============================================================================
# Constants
# =============================================================================

UDP_DATA_MAGIC = 0x55445046  # "UDPF"
UDP_REQUEST_FILE = b"GETF"
UDP_PAYLOAD_SIZE = 1400
UDP_RECEIVE_BUFFER = 2048
UDP_MAX_RETRIES = 5
UDP_IDLE_TIMEOUT_SECONDS = 1.0
UDP_TRANSFER_TIMEOUT_SECONDS = 30.0


class NetworkDownloadAnalyzer:
    """
    Production-ready network download analyzer.

    Features:
    - Protocol selection (TCP or UDP) via flag
    - Variable file size request
    - Variable test duration
    - Comprehensive metrics collection
    - Thread-safe result storage
    - JSON result export
    """

    def __init__(
        self,
        target_url: str,
        protocol: str = 'tcp',
        file_size_mb: Optional[int] = None,
        duration_seconds: int = 3600,
        interval_seconds: int = 60,
        timeout_seconds: int = 30,
        results_dir: str = "results"
    ):
        """
        Initialize the analyzer.

        Args:
            target_url: URL to download from (http:// or https://)
            protocol: 'tcp' or 'udp' (default: 'tcp')
            file_size_mb: Requested file size in MB (optional)
            duration_seconds: Total test duration (default: 3600)
            interval_seconds: Time between downloads (default: 60)
            timeout_seconds: Socket timeout (default: 30)
            results_dir: Directory for results (default: "results")
        """
        # Validate protocol
        self.protocol = protocol.lower()
        if self.protocol not in ('tcp', 'udp'):
            raise ValueError(f"Invalid protocol: {protocol}. Use 'tcp' or 'udp'")

        # Parse URL
        self.target_url = target_url
        self.hostname, self.port, self.use_ssl, self.path = self._parse_url(target_url)

        # Configuration
        self.file_size_mb = file_size_mb
        self.duration_seconds = duration_seconds
        self.interval_seconds = interval_seconds
        self.timeout_seconds = timeout_seconds
        self.results_dir = results_dir

        # Results storage (thread-safe)
        self.results: List[Dict] = []
        self._results_lock = threading.Lock()

        # Statistics
        self.stats = {
            'total_downloads': 0,
            'successful_downloads': 0,
            'failed_downloads': 0,
        }

        # Session info
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create results directory
        os.makedirs(self.results_dir, exist_ok=True)

        print(f"[INIT] Network Download Analyzer")
        print(f"[INIT] Target: {self.hostname}:{self.port}")
        print(f"[INIT] Protocol: {self.protocol.upper()}")
        print(f"[INIT] SSL/TLS: {'Yes' if self.use_ssl else 'No'}")
        print(f"[INIT] Duration: {duration_seconds}s")
        print(f"[INIT] Interval: {interval_seconds}s")
        print(f"[INIT] Session: {self.session_id}")

    def _parse_url(self, url: str) -> Tuple[str, int, bool, str]:
        """Parse URL and extract connection parameters."""
        parsed = urlparse(url)

        if parsed.scheme == 'https':
            use_ssl = True
            default_port = 443
        elif parsed.scheme == 'http':
            use_ssl = False
            default_port = 80
        else:
            raise ValueError(f"Unsupported scheme: {parsed.scheme}")

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Missing hostname in URL")

        port = parsed.port if parsed.port else default_port
        path = parsed.path if parsed.path else '/'
        if parsed.query:
            path += '?' + parsed.query

        return hostname, port, use_ssl, path

    # =========================================================================
    # UDP Control Channel
    # =========================================================================

    def _send_udp_command(self, command: str, udp_port: int) -> Optional[str]:
        """Send UDP control command to server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.sendto(command.encode(), (self.hostname, udp_port))
            response, _ = sock.recvfrom(1024)
            sock.close()
            return response.decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            print(f"[UDP] Timeout waiting for response")
            return None
        except Exception as e:
            print(f"[UDP] Error: {e}")
            return None

    def _set_server_file_size(self, size_mb: int, udp_port: int) -> bool:
        """Request server to change file size via UDP."""
        print(f"[UDP] Requesting file size: {size_mb}MB...")
        response = self._send_udp_command(f"SET_SIZE:{size_mb}", udp_port)

        if response and response.startswith("OK:"):
            new_size = int(response.split(':')[1])
            print(f"[UDP] Server confirmed: {new_size}MB")
            return True
        elif response:
            print(f"[UDP] Server response: {response}")
        return False

    def _get_server_file_size(self, udp_port: int) -> Optional[int]:
        """Query current file size from server via UDP."""
        response = self._send_udp_command("GET_SIZE", udp_port)
        if response and response.startswith("SIZE:"):
            try:
                size = int(response.split(':')[1])
                print(f"[UDP] Current server file size: {size}MB")
                return size
            except (ValueError, IndexError):
                pass
        return None

    # =========================================================================
    # UDP File Transfer
    # =========================================================================

    def _download_udp(self, download_num: int, udp_port: int) -> Dict:
        """
        Download file over UDP with missing-packet retransmission.

        Packet format (20-byte header + payload):
        - Magic (4 bytes): 0x55445046
        - Sequence (4 bytes): packet index
        - Total chunks (4 bytes): total packets
        - Chunk size (4 bytes): payload size
        - Total size (4 bytes): full file size
        - Payload: up to 1400 bytes
        """
        result = {
            "timestamp": datetime.now().isoformat(),
            "hostname": self.hostname,
            "port": udp_port,
            "protocol": "udp",
            "success": False,
            "file_size_bytes": 0,
            "download_time_seconds": 0,
            "download_speed_mbps": 0,
            "md5_checksum": None,
            "packets_expected": 0,
            "packets_received": 0,
            "packets_retransmitted": 0,
            "udp_retries": 0,
            "error": None,
            "error_type": None
        }

        sock = None

        try:
            print(f"\n[UDP #{download_num}] Starting download from {self.hostname}:{udp_port}")

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(UDP_IDLE_TIMEOUT_SECONDS)

            download_start = time.time()

            # Send file request
            sock.sendto(UDP_REQUEST_FILE, (self.hostname, udp_port))
            print(f"[UDP #{download_num}] File request sent")

            # Collect packets
            chunks: Dict[int, bytes] = {}
            total_chunks: Optional[int] = None
            total_file_size: Optional[int] = None
            retries = 0

            while time.time() - download_start < UDP_TRANSFER_TIMEOUT_SECONDS:
                try:
                    data, addr = sock.recvfrom(UDP_RECEIVE_BUFFER)

                    if len(data) < 20:
                        continue

                    magic, seq, total, chunk_size, file_size = struct.unpack('!IIIII', data[:20])

                    if magic != UDP_DATA_MAGIC:
                        continue
                    if seq >= total:
                        continue
                    if len(data) - 20 < chunk_size:
                        continue

                    # Store metadata
                    if total_chunks is None:
                        total_chunks = total
                        total_file_size = file_size
                        result["packets_expected"] = total_chunks
                        print(f"[UDP #{download_num}] Transfer: {total_file_size} bytes, {total_chunks} packets")

                    elif total != total_chunks or file_size != total_file_size:
                        continue

                    # Store payload
                    payload = data[20:20 + chunk_size]
                    chunks[seq] = payload

                    if len(chunks) % 100 == 0 and len(chunks) > 0:
                        print(f"[UDP #{download_num}] Progress: {len(chunks)}/{total_chunks}")

                    if len(chunks) == total_chunks:
                        break

                except socket.timeout:
                    if total_chunks is None:
                        retries += 1
                        if retries > UDP_MAX_RETRIES:
                            raise TimeoutError("No response from server")
                        sock.sendto(UDP_REQUEST_FILE, (self.hostname, udp_port))
                        print(f"[UDP #{download_num}] Retrying request ({retries}/{UDP_MAX_RETRIES})")
                        continue

                    missing = [s for s in range(total_chunks) if s not in chunks]
                    if not missing:
                        break

                    if retries >= UDP_MAX_RETRIES:
                        print(f"[UDP #{download_num}] Max retries reached, {len(missing)} packets missing")
                        break

                    retries += 1
                    result["udp_retries"] = retries
                    result["packets_retransmitted"] += len(missing)

                    # Request missing packets in batches
                    for i in range(0, len(missing), 100):
                        batch = missing[i:i + 100]
                        cmd = "GET_MISSING:" + ",".join(str(s) for s in batch)
                        sock.sendto(cmd.encode(), (self.hostname, udp_port))
                        print(f"[UDP #{download_num}] Requesting {len(batch)} missing packets")

            # Calculate metrics
            download_time = time.time() - download_start
            result["download_time_seconds"] = download_time
            result["packets_received"] = len(chunks)

            # Reassemble file
            if chunks and total_chunks is not None:
                file_data = b''.join(chunks.get(i, b'') for i in range(total_chunks))
                result["file_size_bytes"] = len(file_data)
                result["md5_checksum"] = hashlib.md5(file_data).hexdigest()

                if download_time > 0:
                    result["download_speed_mbps"] = (len(file_data) * 8) / (download_time * 1_000_000)

                # Verify completeness
                if len(chunks) != total_chunks:
                    result["error"] = f"Incomplete: {total_chunks - len(chunks)} packets missing"
                    result["error_type"] = "incomplete"
                elif len(file_data) != total_file_size:
                    result["error"] = f"Incomplete: expected {total_file_size}, got {len(file_data)}"
                    result["error_type"] = "incomplete"
                else:
                    result["success"] = True
                    print(f"[UDP #{download_num}] SUCCESS: {len(file_data) / (1024*1024):.2f}MB "
                          f"in {download_time:.2f}s ({result['download_speed_mbps']:.2f} Mbps)")
            else:
                result["error"] = "No data received"
                result["error_type"] = "no_data"

        except socket.timeout:
            result["error"] = "UDP socket timeout"
            result["error_type"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
            result["error_type"] = "general_error"
            print(f"[UDP #{download_num}] ERROR: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        return result

    # =========================================================================
    # TCP Download (with optional SSL)
    # =========================================================================

    def _download_tcp(self, download_num: int) -> Dict:
        """Download file over TCP with optional SSL/TLS."""
        result = {
            "timestamp": datetime.now().isoformat(),
            "hostname": self.hostname,
            "port": self.port,
            "protocol": "tcp",
            "ssl_enabled": self.use_ssl,
            "success": False,
            "status_code": None,
            "file_size_bytes": 0,
            "download_time_seconds": 0,
            "connection_time_ms": 0,
            "ssl_handshake_time_ms": 0,
            "download_speed_mbps": 0,
            "md5_checksum": None,
            "error": None,
            "error_type": None
        }

        sock = None

        try:
            print(f"\n[TCP #{download_num}] Starting download from {self.hostname}:{self.port}")

            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_seconds)
            print(f"[TCP #{download_num}] Socket created")

            # Connect
            connect_start = time.time()
            sock.connect((self.hostname, self.port))
            result["connection_time_ms"] = (time.time() - connect_start) * 1000
            print(f"[TCP #{download_num}] Connected ({result['connection_time_ms']:.1f}ms)")

            # SSL wrap if needed
            if self.use_ssl:
                ssl_start = time.time()
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.hostname)
                result["ssl_handshake_time_ms"] = (time.time() - ssl_start) * 1000
                print(f"[TCP #{download_num}] SSL handshake complete ({result['ssl_handshake_time_ms']:.1f}ms)")

            # Send HTTP GET
            request = f"GET {self.path} HTTP/1.1\r\nHost: {self.hostname}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())
            print(f"[TCP #{download_num}] HTTP request sent")

            # Receive response
            download_start = time.time()
            response_data = b""

            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response_data += chunk

            result["download_time_seconds"] = time.time() - download_start

            # Parse HTTP response
            header_end = response_data.find(b"\r\n\r\n")
            if header_end == -1:
                raise ValueError("Invalid HTTP response")

            headers_raw = response_data[:header_end].decode('utf-8', errors='ignore')
            body = response_data[header_end + 4:]

            # Parse status code
            status_line = headers_raw.split('\r\n')[0]
            parts = status_line.split(' ')
            if len(parts) >= 2:
                result["status_code"] = int(parts[1])

            if result["status_code"] != 200:
                raise ValueError(f"HTTP {result['status_code']}")

            # Calculate metrics
            result["file_size_bytes"] = len(body)
            result["md5_checksum"] = hashlib.md5(body).hexdigest()

            if result["download_time_seconds"] > 0:
                result["download_speed_mbps"] = (len(body) * 8) / (result["download_time_seconds"] * 1_000_000)

            result["success"] = True
            print(f"[TCP #{download_num}] SUCCESS: {len(body) / (1024*1024):.2f}MB "
                  f"in {result['download_time_seconds']:.2f}s ({result['download_speed_mbps']:.2f} Mbps)")

        except socket.timeout:
            result["error"] = "Connection timeout"
            result["error_type"] = "timeout"
        except ssl.SSLError as e:
            result["error"] = f"SSL error: {e}"
            result["error_type"] = "ssl_error"
        except ConnectionRefusedError:
            result["error"] = "Connection refused"
            result["error_type"] = "connection_refused"
        except Exception as e:
            result["error"] = str(e)
            result["error_type"] = "general_error"
            print(f"[TCP #{download_num}] ERROR: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        return result

    # =========================================================================
    # Main Analysis Loop
    # =========================================================================

    def run_analysis(self, udp_port: Optional[int] = None):
        """
        Execute the download analysis.

        Args:
            udp_port: UDP port for control commands (required for UDP protocol)
        """
        if self.protocol == 'udp' and udp_port is None:
            raise ValueError("UDP port required for UDP protocol")

        print()
        print("=" * 70)
        print("NETWORK DOWNLOAD ANALYSIS")
        print("=" * 70)
        print(f"Session:    {self.session_id}")
        print(f"Target:     {self.target_url}")
        print(f"Protocol:   {self.protocol.upper()}")
        print(f"Duration:   {self.duration_seconds}s")
        print(f"Interval:   {self.interval_seconds}s")
        print("=" * 70)
        print()

        # Set file size via UDP if requested
        if self.file_size_mb is not None and udp_port:
            self._set_server_file_size(self.file_size_mb, udp_port)
            time.sleep(1)  # Let server regenerate file
        elif udp_port:
            self._get_server_file_size(udp_port)

        start_time = time.time()
        download_count = 0

        try:
            while (time.time() - start_time) < self.duration_seconds:
                elapsed = time.time() - start_time
                download_count += 1

                print(f"\n{'=' * 70}")
                print(f"DOWNLOAD #{download_count} (elapsed: {elapsed:.1f}s)")
                print(f"{'=' * 70}")

                # Perform download
                if self.protocol == 'udp':
                    result = self._download_udp(download_count, udp_port)
                else:
                    result = self._download_tcp(download_count)

                # Store result
                with self._results_lock:
                    self.results.append(result)

                # Update stats
                self.stats['total_downloads'] = download_count
                if result["success"]:
                    self.stats['successful_downloads'] += 1
                else:
                    self.stats['failed_downloads'] += 1

                # Wait for next interval
                remaining = self.duration_seconds - elapsed
                if remaining > self.interval_seconds:
                    print(f"\n[INFO] Next download in {self.interval_seconds}s")
                    time.sleep(self.interval_seconds)
                else:
                    print(f"\n[INFO] Session ending - insufficient time for another download")
                    break

        except KeyboardInterrupt:
            print("\n[INFO] Analysis interrupted by user")

        finally:
            # Save results
            self._save_results()
            self._print_summary()

    def _save_results(self):
        """Save results to JSON file."""
        filename = f"results_{self.session_id}.json"
        filepath = os.path.join(self.results_dir, filename)

        udp_count = sum(1 for r in self.results if r.get("protocol") == "udp")

        output = {
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "url": self.target_url,
                "hostname": self.hostname,
                "port": self.port,
                "protocol": self.protocol,
                "ssl_enabled": self.use_ssl,
                "requested_file_size_mb": self.file_size_mb,
                "duration_seconds": self.duration_seconds,
                "interval_seconds": self.interval_seconds,
                "timeout_seconds": self.timeout_seconds
            },
            "statistics": {
                "total_downloads": self.stats['total_downloads'],
                "successful_downloads": self.stats['successful_downloads'],
                "failed_downloads": self.stats['failed_downloads'],
                "udp_transfers": udp_count,
                "success_rate": (self.stats['successful_downloads'] / self.stats['total_downloads'] * 100)
                    if self.stats['total_downloads'] > 0 else 0
            },
            "results": self.results
        }

        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"\n[SAVE] Results saved: {filepath}")

    def _print_summary(self):
        """Print final analysis summary."""
        print()
        print("=" * 70)
        print("ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"Total Downloads:    {self.stats['total_downloads']}")
        print(f"Successful:         {self.stats['successful_downloads']}")
        print(f"Failed:             {self.stats['failed_downloads']}")

        if self.stats['total_downloads'] > 0:
            rate = (self.stats['successful_downloads'] / self.stats['total_downloads']) * 100
            print(f"Success Rate:       {rate:.1f}%")

        # Performance stats
        successful = [r for r in self.results if r["success"]]

        if successful:
            speeds = [r["download_speed_mbps"] for r in successful]

            import statistics

            print()
            print("SPEED STATISTICS (Mbps):")
            print(f"  Average: {statistics.mean(speeds):.2f}")
            print(f"  Median:  {statistics.median(speeds):.2f}")
            print(f"  Min:     {min(speeds):.2f}")
            print(f"  Max:     {max(speeds):.2f}")

            if len(speeds) > 1:
                print(f"  Std Dev: {statistics.stdev(speeds):.2f}")

        print("=" * 70)


# =============================================================================
# Command Line Interface
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Network Download Analyzer with TCP/UDP Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # TCP download, 10MB file, 1 hour duration, 5 minute intervals
  python network_analyzer.py --protocol tcp --size 10 --duration 3600 --interval 300 http://server:8443/test

  # UDP download, 5MB file, 30 minute duration
  python network_analyzer.py --protocol udp --size 5 --duration 1800 --udp-port 8443 http://server:8443/test

  # Quick test (5 downloads, 10 second intervals)
  python network_analyzer.py --protocol tcp --test http://localhost:8443/test
        """
    )

    parser.add_argument(
        'url',
        help='URL to download from (http:// or https://)'
    )

    parser.add_argument(
        '--protocol',
        type=str,
        default='tcp',
        choices=['tcp', 'udp'],
        help='Protocol: tcp or udp (default: tcp)'
    )

    parser.add_argument(
        '--size',
        type=int,
        default=None,
        help='Request file size from server in MB'
    )

    parser.add_argument(
        '--duration',
        type=int,
        default=3600,
        help='Total test duration in seconds (default: 3600)'
    )

    parser.add_argument(
        '--interval',
        type=int,
        default=60,
        help='Time between downloads in seconds (default: 60)'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Socket timeout in seconds (default: 30)'
    )

    parser.add_argument(
        '--results-dir',
        type=str,
        default='results',
        help='Results directory (default: results)'
    )

    parser.add_argument(
        '--udp-port',
        type=int,
        default=8443,
        help='UDP port for control/file transfer (default: 8443)'
    )

    parser.add_argument(
        '--test',
        action='store_true',
        help='Test mode: 5 downloads at 10 second intervals'
    )

    args = parser.parse_args()

    # Test mode
    if args.test:
        print("=" * 70)
        print("TEST MODE")
        print("5 downloads at 10 second intervals")
        print("=" * 70)
        args.duration = 60
        args.interval = 10

    try:
        analyzer = NetworkDownloadAnalyzer(
            target_url=args.url,
            protocol=args.protocol,
            file_size_mb=args.size,
            duration_seconds=args.duration,
            interval_seconds=args.interval,
            timeout_seconds=args.timeout,
            results_dir=args.results_dir
        )

        analyzer.run_analysis(udp_port=args.udp_port)

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"\n[FATAL] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
