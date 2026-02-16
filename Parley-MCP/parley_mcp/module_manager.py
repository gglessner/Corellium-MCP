"""
Parley-MCP Module Manager

Dynamically compiles and executes traffic modification modules from code
stored in the database. Provides caching, validation, and a thread-safe
processing pipeline.

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

import sys
import os
import threading
import traceback
import inspect
from typing import Callable, Tuple

# Ensure module_libs is importable by modules
_module_libs_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'module_libs'
)
if _module_libs_path not in sys.path:
    sys.path.insert(0, _module_libs_path)


class ModuleManager:
    """Manages dynamic compilation and execution of traffic modification modules."""

    def __init__(self, database):
        self.db = database
        self._cache = {}  # {module_id: (code_hash, compiled_function)}
        self._lock = threading.Lock()

    def compile_module(self, module_id: str, name: str, code: str) -> Callable:
        """Compile module code and extract module_function.

        Args:
            module_id: Unique module identifier
            name: Human-readable module name
            code: Python source code that must define module_function()

        Returns:
            The compiled module_function callable

        Raises:
            ValueError: If module_function is not defined or has wrong signature
            SyntaxError: If the code has syntax errors
        """
        module_globals = {
            '__builtins__': __builtins__,
            '__name__': f'parley_module_{name}',
        }

        compiled = compile(code, f"<module:{name}>", "exec")
        exec(compiled, module_globals)

        func = module_globals.get('module_function')
        if func is None:
            raise ValueError(
                f"Module '{name}' does not define module_function(). "
                f"Required signature: def module_function(message_num, source_ip, "
                f"source_port, dest_ip, dest_port, message_data) -> message_data"
            )

        return func

    def get_compiled_function(self, module_id: str, name: str,
                              code: str) -> Callable:
        """Get a compiled module function, using cache when possible.

        The cache is keyed by module_id and invalidated when code changes.
        """
        code_hash = hash(code)
        with self._lock:
            cached = self._cache.get(module_id)
            if cached and cached[0] == code_hash:
                return cached[1]

            # Compile and cache
            func = self.compile_module(module_id, name, code)
            self._cache[module_id] = (code_hash, func)
            return func

    def invalidate(self, module_id: str = None):
        """Invalidate module cache.

        Args:
            module_id: Specific module to invalidate, or None for all
        """
        with self._lock:
            if module_id:
                self._cache.pop(module_id, None)
            else:
                self._cache.clear()

    def process_message(self, instance_id: str, direction: str,
                        message_num: int, source_ip: str, source_port: int,
                        dest_ip: str, dest_port: int,
                        message_data: bytearray) -> bytearray:
        """Process a message through all enabled modules for an instance/direction.

        Modules are executed in priority order (lower priority number = runs first).
        If a module raises an exception, it is logged and skipped.

        Args:
            instance_id: The proxy instance ID
            direction: 'client' or 'server'
            message_num: Sequential message number for this connection/direction
            source_ip: Source IP address
            source_port: Source port
            dest_ip: Destination IP address
            dest_port: Destination port
            message_data: The message data to process

        Returns:
            The (potentially modified) message data as bytearray
        """
        modules = self.db.get_enabled_modules(instance_id, direction)

        for mod in modules:
            try:
                func = self.get_compiled_function(
                    mod['id'], mod['name'], mod['code']
                )
                result = func(
                    message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data
                )
                if result is not None:
                    if not isinstance(result, bytearray):
                        message_data = bytearray(result)
                    else:
                        message_data = result
            except Exception as e:
                # Log error but don't break the proxy pipeline
                print(f"[!] Module '{mod['name']}' ({mod['id']}) error: {e}",
                      file=sys.stderr)
                traceback.print_exc(file=sys.stderr)

        return message_data

    def validate_module_code(self, code: str) -> Tuple[bool, str]:
        """Validate module code without side effects.

        Compiles the code and checks that module_function is defined
        with the correct signature.

        Returns:
            (is_valid, error_message) tuple
        """
        try:
            compiled = compile(code, "<validation>", "exec")
            test_globals = {'__builtins__': __builtins__}
            exec(compiled, test_globals)

            if 'module_function' not in test_globals:
                return False, (
                    "Module code must define module_function(). "
                    "Required: def module_function(message_num, source_ip, "
                    "source_port, dest_ip, dest_port, message_data)"
                )

            func = test_globals['module_function']
            if not callable(func):
                return False, "module_function must be callable"

            # Check parameter count
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            if len(params) != 6:
                return False, (
                    f"module_function should accept exactly 6 parameters "
                    f"(message_num, source_ip, source_port, dest_ip, dest_port, "
                    f"message_data), got {len(params)}: {params}"
                )

            return True, "OK"

        except SyntaxError as e:
            return False, f"Syntax error at line {e.lineno}: {e.msg}"
        except Exception as e:
            return False, f"Validation error: {e}"
