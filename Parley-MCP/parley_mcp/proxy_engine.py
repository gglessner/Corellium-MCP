"""
Parley-MCP Proxy Engine

Multi-threaded TCP/TLS proxy adapted from Parley for MCP integration.
Each proxy instance runs its own listener thread and spawns handler threads
for each connection. All traffic is logged to SQLite and processed through
the dynamic module pipeline.

Copyright (C) 2025 Garland Glessner (gglessner@gmail.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.
"""

import socket
import ssl
import threading
import select
import traceback
import sys
from typing import Dict, Any, Optional


class ProxyInstance:
    """A single running proxy instance with its threads and sockets."""

    def __init__(self, instance_id: str, config: Dict[str, Any],
                 database, module_manager):
        self.instance_id = instance_id
        self.config = config
        self.db = database
        self.module_manager = module_manager
        self.server_socket: Optional[socket.socket] = None
        self.listener_thread: Optional[threading.Thread] = None
        self.handler_threads: list = []
        self._stop_event = threading.Event()
        self._active_connections = 0
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return not self._stop_event.is_set()

    @property
    def active_connections(self) -> int:
        return self._active_connections

    def start(self):
        """Start the proxy listener on the configured host:port."""
        cfg = self.config
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)  # Allow periodic stop checks
        self.server_socket.bind((cfg['listen_host'], cfg['listen_port']))
        self.server_socket.listen(5)

        self.listener_thread = threading.Thread(
            target=self._listener_loop,
            name=f"parley-listener-{self.instance_id}",
            daemon=True
        )
        self.listener_thread.start()

    def stop(self):
        """Stop the proxy listener and all active connections."""
        self._stop_event.set()

        # Close the server socket to unblock accept()
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        # Wait for listener thread
        if self.listener_thread:
            self.listener_thread.join(timeout=5)

        # Wait for handler threads
        for t in self.handler_threads:
            t.join(timeout=2)

        self.db.update_instance_status(self.instance_id, 'stopped')

    def _listener_loop(self):
        """Accept incoming connections in a loop until stopped."""
        while not self._stop_event.is_set():
            try:
                client_socket, addr = self.server_socket.accept()
                handler = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket,),
                    name=f"parley-handler-{self.instance_id}-{addr[0]}:{addr[1]}",
                    daemon=True
                )
                with self._lock:
                    self.handler_threads.append(handler)
                handler.start()
            except socket.timeout:
                continue  # Check stop event and loop
            except OSError:
                if not self._stop_event.is_set():
                    traceback.print_exc(file=sys.stderr)
                break

    def _handle_connection(self, client_socket: socket.socket):
        """Handle a single proxied connection with bidirectional data shuttle."""
        cfg = self.config
        forward_socket = None
        connection_id = None
        sockets_list = []

        with self._lock:
            self._active_connections += 1

        try:
            # Connect to target server
            forward_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            forward_socket.connect((cfg['target_host'], cfg['target_port']))

            client_ip, client_port = client_socket.getpeername()
            server_ip, server_port = forward_socket.getpeername()

            # Log connection to database
            connection_id = self.db.create_connection(
                self.instance_id, client_ip, client_port, server_ip, server_port
            )

            # === TLS wrapping: server side (outbound to target) ===
            if cfg.get('use_tls_server'):
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                if cfg.get('no_verify'):
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                if cfg.get('client_certfile') and cfg.get('client_keyfile'):
                    context.load_cert_chain(
                        certfile=cfg['client_certfile'],
                        keyfile=cfg['client_keyfile']
                    )
                if cfg.get('cipher'):
                    context.set_ciphers(cfg['cipher'])
                if cfg.get('ssl_version'):
                    ssl_opts = {
                        'TLSv1': (ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                                  | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2),
                        'TLSv1.1': (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2
                                    | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2),
                        'TLSv1.2': (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
                                    | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2),
                    }
                    if cfg['ssl_version'] in ssl_opts:
                        context.options |= ssl_opts[cfg['ssl_version']]
                forward_socket = context.wrap_socket(
                    forward_socket, server_hostname=cfg['target_host']
                )

            # === TLS wrapping: client side (inbound from client) ===
            if cfg.get('use_tls_client'):
                client_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                if cfg.get('certfile') and cfg.get('keyfile'):
                    client_context.load_cert_chain(
                        certfile=cfg['certfile'], keyfile=cfg['keyfile']
                    )
                client_socket = client_context.wrap_socket(
                    client_socket, server_side=True
                )

            # === Bidirectional data shuttle ===
            sockets_list = [client_socket, forward_socket]
            buffer_size = 65536
            client_msg_num = 0
            server_msg_num = 0

            while sockets_list and not self._stop_event.is_set():
                readable, _, _ = select.select(sockets_list, [], [], 1.0)

                for s in readable:
                    full_data = bytearray()
                    while True:
                        data = s.recv(buffer_size)
                        if not data:
                            break
                        full_data.extend(data)
                        # For SSL sockets, drain all pending records
                        # from the SSL buffer before returning
                        if hasattr(s, 'pending') and s.pending() > 0:
                            continue
                        if len(data) < buffer_size:
                            break

                    if full_data:
                        if s is client_socket:
                            # Client -> Server
                            client_msg_num += 1
                            original_data = bytes(full_data)

                            # Process through module pipeline
                            full_data = self.module_manager.process_message(
                                self.instance_id, 'client', client_msg_num,
                                client_ip, client_port, server_ip, server_port,
                                full_data
                            )

                            modified_data = bytes(full_data)
                            was_modified = original_data != modified_data

                            # Log to SQLite
                            self.db.log_message(
                                self.instance_id, connection_id,
                                'client_to_server', client_msg_num,
                                client_ip, client_port,
                                server_ip, server_port,
                                original_data,
                                modified_data if was_modified else None,
                                was_modified
                            )

                            forward_socket.sendall(full_data)

                        else:
                            # Server -> Client
                            server_msg_num += 1
                            original_data = bytes(full_data)

                            # Process through module pipeline
                            full_data = self.module_manager.process_message(
                                self.instance_id, 'server', server_msg_num,
                                server_ip, server_port, client_ip, client_port,
                                full_data
                            )

                            modified_data = bytes(full_data)
                            was_modified = original_data != modified_data

                            # Log to SQLite
                            self.db.log_message(
                                self.instance_id, connection_id,
                                'server_to_client', server_msg_num,
                                server_ip, server_port,
                                client_ip, client_port,
                                original_data,
                                modified_data if was_modified else None,
                                was_modified
                            )

                            client_socket.sendall(full_data)
                    else:
                        # Socket closed - end the proxied session.
                        # When either side disconnects, the proxy is done.
                        # Close all sockets and clear the list so the
                        # outer while-loop exits too.
                        for sock in list(sockets_list):
                            try:
                                sock.close()
                            except Exception:
                                pass
                        sockets_list.clear()
                        break

        except OSError as e:
            # Common disconnection errors (cross-platform errnos)
            if e.errno in (9, 10038, 10053, 10054, 54, 104):
                pass  # Expected: bad fd, not a socket, conn aborted/reset
            elif not self._stop_event.is_set():
                print(f"[!] Connection error ({self.instance_id}): {e}",
                      file=sys.stderr)
        except Exception as e:
            if not self._stop_event.is_set():
                print(f"[!] Connection error ({self.instance_id}): {e}",
                      file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
        finally:
            # Clean up sockets
            for s in sockets_list:
                try:
                    s.close()
                except Exception:
                    pass
            if forward_socket and forward_socket not in sockets_list:
                try:
                    forward_socket.close()
                except Exception:
                    pass

            # Mark connection as ended in database
            if connection_id:
                try:
                    self.db.end_connection(connection_id)
                except Exception:
                    pass

            with self._lock:
                self._active_connections -= 1


class ProxyEngine:
    """Manages the lifecycle of all proxy instances."""

    def __init__(self, database, module_manager):
        self.db = database
        self.module_manager = module_manager
        self._instances: Dict[str, ProxyInstance] = {}
        self._lock = threading.Lock()

    def start_instance(self, instance_id: str,
                       config: Dict[str, Any]) -> ProxyInstance:
        """Create and start a new proxy instance.

        Args:
            instance_id: Unique identifier for this instance
            config: Proxy configuration dict with listen/target/TLS settings

        Returns:
            The started ProxyInstance
        """
        instance = ProxyInstance(
            instance_id, config, self.db, self.module_manager
        )
        instance.start()

        with self._lock:
            self._instances[instance_id] = instance

        return instance

    def stop_instance(self, instance_id: str) -> bool:
        """Stop a running proxy instance.

        Returns:
            True if the instance was found and stopped
        """
        with self._lock:
            instance = self._instances.pop(instance_id, None)

        if instance:
            instance.stop()
            return True
        return False

    def get_instance(self, instance_id: str) -> Optional[ProxyInstance]:
        """Get a running proxy instance by ID."""
        with self._lock:
            return self._instances.get(instance_id)

    def list_running(self) -> Dict[str, ProxyInstance]:
        """Get all currently running proxy instances."""
        with self._lock:
            return dict(self._instances)

    def shutdown_all(self):
        """Stop all running proxy instances. Called on server shutdown."""
        with self._lock:
            instances = list(self._instances.values())
            self._instances.clear()

        for instance in instances:
            try:
                instance.stop()
            except Exception:
                pass
