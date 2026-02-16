"""
Parley-MCP Database Layer

SQLite3 storage for proxy instances, connections, traffic data, and modules.
Thread-safe via WAL mode and thread-local connections.

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

import sqlite3
import threading
import os
import uuid
from typing import Optional, List, Dict, Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS instances (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    listen_host TEXT NOT NULL DEFAULT 'localhost',
    listen_port INTEGER NOT NULL DEFAULT 8080,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL DEFAULT 80,
    use_tls_client INTEGER NOT NULL DEFAULT 0,
    use_tls_server INTEGER NOT NULL DEFAULT 0,
    no_verify INTEGER NOT NULL DEFAULT 0,
    certfile TEXT,
    keyfile TEXT,
    client_certfile TEXT,
    client_keyfile TEXT,
    cipher TEXT,
    ssl_version TEXT,
    status TEXT NOT NULL DEFAULT 'stopped',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    stopped_at TEXT
);

CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    client_port INTEGER NOT NULL,
    server_ip TEXT NOT NULL,
    server_port INTEGER NOT NULL,
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    ended_at TEXT,
    FOREIGN KEY (instance_id) REFERENCES instances(id)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL,
    connection_id INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('client_to_server', 'server_to_client')),
    message_num INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    original_data BLOB,
    modified_data BLOB,
    was_modified INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    FOREIGN KEY (instance_id) REFERENCES instances(id),
    FOREIGN KEY (connection_id) REFERENCES connections(id)
);

CREATE TABLE IF NOT EXISTS modules (
    id TEXT PRIMARY KEY,
    instance_id TEXT,
    name TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('client', 'server')),
    description TEXT NOT NULL DEFAULT '',
    code TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 100,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_instance ON messages(instance_id);
CREATE INDEX IF NOT EXISTS idx_messages_connection ON messages(connection_id);
CREATE INDEX IF NOT EXISTS idx_messages_direction ON messages(direction);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_connections_instance ON connections(instance_id);
CREATE INDEX IF NOT EXISTS idx_modules_instance ON modules(instance_id);
CREATE INDEX IF NOT EXISTS idx_modules_direction ON modules(direction);
CREATE INDEX IF NOT EXISTS idx_modules_enabled ON modules(enabled);
"""


class Database:
    """Thread-safe SQLite database for Parley-MCP."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create a thread-local database connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self):
        """Initialize database schema."""
        conn = self._get_conn()
        conn.executescript(SCHEMA)
        conn.commit()

    def cleanup_stale_instances(self):
        """Mark any 'running' instances as 'stopped' (for server restart)."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE instances SET status='stopped', "
            "stopped_at=strftime('%Y-%m-%dT%H:%M:%f', 'now') "
            "WHERE status='running'"
        )
        conn.commit()

    # ===== Instance operations =====

    def create_instance(self, name: str, target_host: str, target_port: int = 80,
                        listen_host: str = "localhost", listen_port: int = 8080,
                        use_tls_client: bool = False, use_tls_server: bool = False,
                        no_verify: bool = False, certfile: str = None, keyfile: str = None,
                        client_certfile: str = None, client_keyfile: str = None,
                        cipher: str = None, ssl_version: str = None) -> str:
        """Create a new proxy instance record. Returns instance ID."""
        instance_id = str(uuid.uuid4())[:8]
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO instances
               (id, name, listen_host, listen_port, target_host, target_port,
                use_tls_client, use_tls_server, no_verify, certfile, keyfile,
                client_certfile, client_keyfile, cipher, ssl_version, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running')""",
            (instance_id, name, listen_host, listen_port, target_host, target_port,
             int(use_tls_client), int(use_tls_server), int(no_verify),
             certfile, keyfile, client_certfile, client_keyfile, cipher, ssl_version)
        )
        conn.commit()
        return instance_id

    def update_instance_status(self, instance_id: str, status: str):
        """Update the status of an instance."""
        conn = self._get_conn()
        if status == 'stopped':
            conn.execute(
                "UPDATE instances SET status=?, "
                "stopped_at=strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id=?",
                (status, instance_id)
            )
        else:
            conn.execute(
                "UPDATE instances SET status=? WHERE id=?",
                (status, instance_id)
            )
        conn.commit()

    def get_instance(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get instance details by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM instances WHERE id=?", (instance_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_instances(self) -> List[Dict[str, Any]]:
        """List all instances."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM instances ORDER BY created_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    # ===== Connection operations =====

    def create_connection(self, instance_id: str, client_ip: str, client_port: int,
                          server_ip: str, server_port: int) -> int:
        """Log a new connection. Returns connection ID."""
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO connections
               (instance_id, client_ip, client_port, server_ip, server_port)
               VALUES (?, ?, ?, ?, ?)""",
            (instance_id, client_ip, client_port, server_ip, server_port)
        )
        conn.commit()
        return cursor.lastrowid

    def end_connection(self, connection_id: int):
        """Mark a connection as ended."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE connections SET ended_at=strftime('%Y-%m-%dT%H:%M:%f', 'now') "
            "WHERE id=?",
            (connection_id,)
        )
        conn.commit()

    def list_connections(self, instance_id: str) -> List[Dict[str, Any]]:
        """List connections for an instance."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM connections WHERE instance_id=? ORDER BY started_at DESC",
            (instance_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    # ===== Message operations =====

    def log_message(self, instance_id: str, connection_id: int, direction: str,
                    message_num: int, source_ip: str, source_port: int,
                    dest_ip: str, dest_port: int,
                    original_data: bytes, modified_data: bytes = None,
                    was_modified: bool = False) -> int:
        """Log a traffic message. Returns message ID."""
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO messages
               (instance_id, connection_id, direction, message_num,
                source_ip, source_port, dest_ip, dest_port,
                original_data, modified_data, was_modified)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (instance_id, connection_id, direction, message_num,
             source_ip, source_port, dest_ip, dest_port,
             bytes(original_data) if original_data else None,
             bytes(modified_data) if modified_data else None,
             int(was_modified))
        )
        conn.commit()
        return cursor.lastrowid

    def query_messages(self, instance_id: str = None, connection_id: int = None,
                       direction: str = None, limit: int = 50, offset: int = 0,
                       order: str = "ASC") -> List[Dict[str, Any]]:
        """Query traffic messages with filters."""
        conn = self._get_conn()
        conditions = []
        params = []

        if instance_id:
            conditions.append("instance_id=?")
            params.append(instance_id)
        if connection_id:
            conditions.append("connection_id=?")
            params.append(connection_id)
        if direction:
            conditions.append("direction=?")
            params.append(direction)

        where = " AND ".join(conditions) if conditions else "1=1"
        order = order.upper()
        if order not in ("ASC", "DESC"):
            order = "ASC"

        query = f"SELECT * FROM messages WHERE {where} ORDER BY id {order} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def search_messages(self, instance_id: str, pattern: str,
                        direction: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Search traffic messages by text content pattern."""
        conn = self._get_conn()
        conditions = ["instance_id=?"]
        params = [instance_id]

        if direction:
            conditions.append("direction=?")
            params.append(direction)

        # Search in both original and modified data
        conditions.append(
            "(CAST(original_data AS TEXT) LIKE ? OR CAST(modified_data AS TEXT) LIKE ?)"
        )
        like_pattern = f"%{pattern}%"
        params.extend([like_pattern, like_pattern])

        where = " AND ".join(conditions)
        query = f"SELECT * FROM messages WHERE {where} ORDER BY id ASC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_traffic_summary(self, instance_id: str) -> Dict[str, Any]:
        """Get traffic summary statistics for an instance."""
        conn = self._get_conn()

        conn_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM connections WHERE instance_id=?",
            (instance_id,)
        ).fetchone()['cnt']

        stats = conn.execute(
            """SELECT
                COUNT(*) as total_messages,
                SUM(CASE WHEN direction='client_to_server' THEN 1 ELSE 0 END) as client_messages,
                SUM(CASE WHEN direction='server_to_client' THEN 1 ELSE 0 END) as server_messages,
                SUM(CASE WHEN was_modified=1 THEN 1 ELSE 0 END) as modified_messages,
                SUM(LENGTH(original_data)) as total_original_bytes,
                SUM(CASE WHEN direction='client_to_server'
                    THEN LENGTH(original_data) ELSE 0 END) as client_bytes,
                SUM(CASE WHEN direction='server_to_client'
                    THEN LENGTH(original_data) ELSE 0 END) as server_bytes,
                MIN(timestamp) as first_message,
                MAX(timestamp) as last_message
               FROM messages WHERE instance_id=?""",
            (instance_id,)
        ).fetchone()

        return {
            'connection_count': conn_count,
            'total_messages': stats['total_messages'] or 0,
            'client_messages': stats['client_messages'] or 0,
            'server_messages': stats['server_messages'] or 0,
            'modified_messages': stats['modified_messages'] or 0,
            'total_original_bytes': stats['total_original_bytes'] or 0,
            'client_bytes': stats['client_bytes'] or 0,
            'server_bytes': stats['server_bytes'] or 0,
            'first_message': stats['first_message'],
            'last_message': stats['last_message'],
        }

    def clear_traffic(self, instance_id: str) -> Dict[str, int]:
        """Clear traffic data for an instance. Returns counts of deleted records."""
        conn = self._get_conn()

        msg_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM messages WHERE instance_id=?",
            (instance_id,)
        ).fetchone()['cnt']

        conn_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM connections WHERE instance_id=?",
            (instance_id,)
        ).fetchone()['cnt']

        conn.execute("DELETE FROM messages WHERE instance_id=?", (instance_id,))
        conn.execute("DELETE FROM connections WHERE instance_id=?", (instance_id,))
        conn.commit()

        return {'messages_deleted': msg_count, 'connections_deleted': conn_count}

    # ===== Module operations =====

    def create_module(self, name: str, direction: str, code: str,
                      description: str = "", instance_id: str = None,
                      enabled: bool = True, priority: int = 100) -> str:
        """Create a new module. Returns module ID."""
        module_id = str(uuid.uuid4())[:8]
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO modules
               (id, instance_id, name, direction, description, code, enabled, priority)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (module_id, instance_id, name, direction, description, code,
             int(enabled), priority)
        )
        conn.commit()
        return module_id

    def update_module(self, module_id: str, code: str = None, description: str = None,
                      priority: int = None, name: str = None) -> bool:
        """Update a module. Returns True if found."""
        conn = self._get_conn()
        updates = []
        params = []

        if code is not None:
            updates.append("code=?")
            params.append(code)
        if description is not None:
            updates.append("description=?")
            params.append(description)
        if priority is not None:
            updates.append("priority=?")
            params.append(priority)
        if name is not None:
            updates.append("name=?")
            params.append(name)

        if not updates:
            return False

        updates.append("updated_at=strftime('%Y-%m-%dT%H:%M:%f', 'now')")
        params.append(module_id)

        query = f"UPDATE modules SET {', '.join(updates)} WHERE id=?"
        cursor = conn.execute(query, params)
        conn.commit()
        return cursor.rowcount > 0

    def delete_module(self, module_id: str) -> bool:
        """Delete a module. Returns True if found."""
        conn = self._get_conn()
        cursor = conn.execute("DELETE FROM modules WHERE id=?", (module_id,))
        conn.commit()
        return cursor.rowcount > 0

    def set_module_enabled(self, module_id: str, enabled: bool) -> bool:
        """Enable or disable a module. Returns True if found."""
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE modules SET enabled=?, "
            "updated_at=strftime('%Y-%m-%dT%H:%M:%f', 'now') WHERE id=?",
            (int(enabled), module_id)
        )
        conn.commit()
        return cursor.rowcount > 0

    def get_module(self, module_id: str) -> Optional[Dict[str, Any]]:
        """Get a module by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM modules WHERE id=?", (module_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_modules(self, instance_id: str = None,
                     direction: str = None) -> List[Dict[str, Any]]:
        """List modules with optional filters."""
        conn = self._get_conn()
        conditions = []
        params = []

        if instance_id is not None:
            conditions.append("(instance_id=? OR instance_id IS NULL)")
            params.append(instance_id)
        if direction:
            conditions.append("direction=?")
            params.append(direction)

        where = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT * FROM modules WHERE {where} ORDER BY priority ASC, name ASC"

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_enabled_modules(self, instance_id: str,
                            direction: str) -> List[Dict[str, Any]]:
        """Get enabled modules for an instance and direction, sorted by priority."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM modules
               WHERE (instance_id=? OR instance_id IS NULL)
               AND direction=? AND enabled=1
               ORDER BY priority ASC, name ASC""",
            (instance_id, direction)
        ).fetchall()
        return [dict(row) for row in rows]
