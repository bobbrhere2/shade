#!/usr/bin/env python3
"""
Shade WebSocket Server + HTTP Server
End-to-end encrypted messenger (RSA + AES).
SQL injection protection via parameterized queries.
"""

import asyncio
import json
import sqlite3
import os
import socket
import webbrowser
import re
from datetime import datetime
from websockets.server import serve
from websockets.exceptions import ConnectionClosed
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading

# ==================== SERVER CONFIG ====================
HOST = '0.0.0.0'
WS_PORT = 8765
HTTP_PORT = 8000
DB_FILE = 'shade.db'

# ==================== INPUT VALIDATION / SQL INJECTION PROTECTION ====================
def sanitize_input(value):
    """Strip potentially dangerous SQL constructs from user input."""
    if value is None:
        return None
    dangerous_patterns = [';', '--', '/*', '*/', 'xp_', 'exec', 'union', 'select', 'insert', 'update', 'delete', 'drop', 'alter']
    cleaned = str(value)
    for pattern in dangerous_patterns:
        cleaned = cleaned.replace(pattern, '')
    cleaned = re.sub(r'[^a-zA-Z0-9@_\-. ]', '', cleaned)
    return cleaned

def validate_username(username):
    """Username must be 3-30 chars: letters, digits, _, -, ."""
    if not username:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_\-.]{3,30}$', username))

def validate_nickname(nickname):
    """Display name must be 2-50 chars (Latin/Cyrillic letters, digits, spaces, _-. )"""
    if not nickname:
        return False
    return bool(re.match(r'^[a-zA-Zа-яА-Я0-9_ \-.]{2,50}$', nickname))

def validate_password(password):
    """Password hash must be at least 6 characters long."""
    if not password:
        return False
    return len(password) >= 6

# ==================== LOCAL IP DETECTION ====================
def get_local_ip():
    """Return the machine's local network IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip.startswith('127.'):
                return "127.0.0.1"
            return ip
        except:
            return "127.0.0.1"

# ==================== DATABASE ====================
def init_db():
    """Create database tables if they do not exist yet."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            nickname TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT,
            created_at INTEGER NOT NULL,
            settings TEXT DEFAULT '{"hashEnabled": true}'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            delivered BOOLEAN DEFAULT 0,
            FOREIGN KEY (from_user) REFERENCES users(username),
            FOREIGN KEY (to_user) REFERENCES users(username)
        )
    ''')

    conn.commit()
    conn.close()
    print("[+] Database initialized")

def get_user(username):
    """Fetch a user record by username. Returns dict or None."""
    if not validate_username(username):
        return None

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT username, nickname, password_hash, public_key, settings FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            'username': row[0],
            'nickname': row[1],
            'password_hash': row[2],
            'public_key': row[3],
            'settings': json.loads(row[4])
        }
    return None

def create_user(username, nickname, password_hash, public_key=None):
    """Insert a new user. Returns True on success, False if the username is taken."""
    if not validate_username(username) or not validate_nickname(nickname):
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, nickname, password_hash, public_key, created_at, settings) VALUES (?, ?, ?, ?, ?, ?)',
            (username, nickname, password_hash, public_key, int(datetime.now().timestamp()), json.dumps({'hashEnabled': True}))
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def update_user(username, nickname, settings):
    """Update a user's nickname and settings."""
    if not validate_username(username) or not validate_nickname(nickname):
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET nickname = ?, settings = ? WHERE username = ?',
        (nickname, json.dumps(settings), username)
    )
    conn.commit()
    conn.close()
    return True

def update_public_key(username, public_key):
    """Replace the user's stored public key."""
    if not validate_username(username):
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET public_key = ? WHERE username = ?', (public_key, username))
    conn.commit()
    conn.close()
    return True

def update_password(username, password_hash):
    """Replace the user's password hash."""
    if not validate_username(username):
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?', (password_hash, username))
    conn.commit()
    conn.close()
    return True

def save_message(from_user, to_user, encrypted_content):
    """Persist an encrypted message to the database."""
    if not validate_username(from_user) or not validate_username(to_user):
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO messages (from_user, to_user, encrypted_content, timestamp) VALUES (?, ?, ?, ?)',
        (from_user, to_user, encrypted_content, int(datetime.now().timestamp()))
    )
    conn.commit()
    conn.close()
    return True

def get_messages_for_user(username):
    """Return all messages sent or received by the user, ordered by timestamp."""
    if not validate_username(username):
        return []

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, from_user, to_user, encrypted_content, timestamp, delivered
        FROM messages
        WHERE to_user = ? OR from_user = ?
        ORDER BY timestamp ASC
    ''', (username, username))
    rows = cursor.fetchall()
    conn.close()

    messages = []
    for row in rows:
        messages.append({
            'id': row[0],
            'from': row[1],
            'to': row[2],
            'content': row[3],
            'timestamp': row[4],
            'delivered': bool(row[5])
        })
    return messages

def mark_delivered(message_id):
    """Mark a message as delivered."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE messages SET delivered = 1 WHERE id = ?', (message_id,))
    conn.commit()
    conn.close()

def delete_user(username):
    """Delete a user and all messages associated with them."""
    if not validate_username(username):
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    cursor.execute('DELETE FROM messages WHERE from_user = ? OR to_user = ?', (username, username))
    conn.commit()
    conn.close()

def search_users(query, online_users=None):
    """Search users by username or nickname (substring match, case-insensitive on ASCII)."""
    clean_query = sanitize_input(query)
    if not clean_query or len(clean_query) < 2:
        return []

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT username, nickname, public_key
        FROM users
        WHERE username LIKE ? OR nickname LIKE ?
        LIMIT 20
    ''', (f'%{clean_query}%', f'%{clean_query}%'))

    rows = cursor.fetchall()
    conn.close()

    if online_users is None:
        online_users = []

    results = []
    for row in rows:
        results.append({
            'username': row[0],
            'nickname': row[1],
            'public_key': row[2],
            'online': row[0] in online_users
        })

    return results

def get_public_key(username):
    """Return the public key of a user, or None if not found."""
    if not validate_username(username):
        return None

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

# ==================== HTTP SERVER (static frontend) ====================
class CustomHTTPHandler(SimpleHTTPRequestHandler):
    """Serves the frontend directory and adds permissive CORS headers."""
    def __init__(self, *args, **kwargs):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        frontend_dir = os.path.join(base_dir, '..', 'frontend')
        super().__init__(*args, directory=frontend_dir, **kwargs)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def log_message(self, format, *args):
        pass  # Silence per-request HTTP logs

def start_http_server():
    """Run the HTTP server (blocking call, intended to run in a thread)."""
    httpd = HTTPServer(('0.0.0.0', HTTP_PORT), CustomHTTPHandler)
    httpd.serve_forever()

# ==================== WEBSOCKET SERVER ====================
class ShadeServer:
    """WebSocket server handling authentication, message routing and user search."""

    def __init__(self):
        self.clients = {}            # username -> websocket
        self.pending_messages = {}   # username -> list of queued messages (offline)

    async def register(self, websocket, username):
        """Register a connected client and flush any queued messages."""
        self.clients[username] = websocket

        # Deliver messages that arrived while the user was offline
        if username in self.pending_messages:
            for message in self.pending_messages[username]:
                await websocket.send(json.dumps({
                    'type': 'message',
                    'data': message
                }))
            del self.pending_messages[username]

        # Notify everyone else that this user came online
        await self.broadcast({
            'type': 'user_online',
            'data': {'username': username}
        }, exclude=[username])

        print(f"[+] {username} connected")

    async def unregister(self, username):
        """Remove a client and notify others that they went offline."""
        if username in self.clients:
            del self.clients[username]
            await self.broadcast({
                'type': 'user_offline',
                'data': {'username': username}
            })
            print(f"[-] {username} disconnected")

    async def broadcast(self, message, exclude=None):
        """Send a message to every connected client except those in `exclude`."""
        if exclude is None:
            exclude = []
        for username, websocket in self.clients.items():
            if username not in exclude:
                try:
                    await websocket.send(json.dumps(message))
                except:
                    pass

    async def send_to_user(self, username, message):
        """Deliver a message to a user, or queue it if they are offline."""
        if username in self.clients:
            try:
                await self.clients[username].send(json.dumps(message))
                return True
            except:
                return False
        else:
            if username not in self.pending_messages:
                self.pending_messages[username] = []
            self.pending_messages[username].append(message['data'])
            return False

    async def handle_client(self, websocket, path):
        """Per-connection handler: authenticate, then process incoming frames."""
        username = None

        try:
            # The first frame must be an authentication request
            auth_msg = await websocket.recv()
            data = json.loads(auth_msg)

            if data['type'] == 'auth':
                username = data['data']['username']
                password_hash = data['data']['password_hash']
                public_key = data['data'].get('public_key', None)

                if not validate_username(username) or not validate_password(password_hash):
                    await websocket.send(json.dumps({
                        'type': 'auth_error',
                        'data': {'message': 'Invalid credentials format'}
                    }))
                    return

                user = get_user(username)
                if user:
                    # Existing user: verify password
                    if user['password_hash'] != password_hash:
                        await websocket.send(json.dumps({
                            'type': 'auth_error',
                            'data': {'message': 'Invalid password'}
                        }))
                        return

                    # Rotate public key if the client supplied a new one
                    if public_key and user['public_key'] != public_key:
                        update_public_key(username, public_key)
                        user = get_user(username)
                else:
                    # New user: register
                    nickname = data['data'].get('nickname', username)
                    if not validate_nickname(nickname):
                        await websocket.send(json.dumps({
                            'type': 'auth_error',
                            'data': {'message': 'Invalid nickname format'}
                        }))
                        return

                    if not create_user(username, nickname, password_hash, public_key):
                        await websocket.send(json.dumps({
                            'type': 'auth_error',
                            'data': {'message': 'Failed to create user'}
                        }))
                        return
                    user = get_user(username)

                await websocket.send(json.dumps({
                    'type': 'auth_success',
                    'data': {
                        'username': username,
                        'nickname': user['nickname'],
                        'public_key': user['public_key'],
                        'settings': user['settings']
                    }
                }))

                # Send message history
                messages = get_messages_for_user(username)
                if messages:
                    await websocket.send(json.dumps({
                        'type': 'history',
                        'data': messages
                    }))

                await self.register(websocket, username)

                # Main message loop
                async for message in websocket:
                    try:
                        data = json.loads(message)

                        if data['type'] == 'message':
                            to_user = data['data']['to']
                            encrypted_content = data['data']['content']

                            if not validate_username(to_user):
                                continue

                            save_message(username, to_user, encrypted_content)

                            await self.send_to_user(to_user, {
                                'type': 'message',
                                'data': {
                                    'id': 0,
                                    'from': username,
                                    'to': to_user,
                                    'content': encrypted_content,
                                    'timestamp': int(datetime.now().timestamp()),
                                    'delivered': False,
                                    'isFile': data['data'].get('isFile', False),
                                    'fileName': data['data'].get('fileName', None),
                                    'fileSize': data['data'].get('fileSize', None),
                                    'fileType': data['data'].get('fileType', None)
                                }
                            })

                        elif data['type'] == 'delivered':
                            message_id = data['data']['message_id']
                            if isinstance(message_id, int):
                                mark_delivered(message_id)

                        elif data['type'] == 'profile_update':
                            nickname = data['data'].get('nickname')
                            settings = data['data'].get('settings')
                            if nickname and settings and validate_nickname(nickname):
                                update_user(username, nickname, settings)
                                user = get_user(username)
                                await websocket.send(json.dumps({
                                    'type': 'profile_updated',
                                    'data': {
                                        'nickname': user['nickname'],
                                        'settings': user['settings']
                                    }
                                }))

                        elif data['type'] == 'search_users':
                            query = data['data'].get('query', '')
                            if len(query) >= 2:
                                online_users = list(self.clients.keys())
                                results = search_users(query, online_users)
                                await websocket.send(json.dumps({
                                    'type': 'search_results',
                                    'data': results
                                }))

                        elif data['type'] == 'get_public_key':
                            target = data['data'].get('username')
                            if target and validate_username(target):
                                pub_key = get_public_key(target)
                                await websocket.send(json.dumps({
                                    'type': 'public_key_response',
                                    'data': {
                                        'username': target,
                                        'public_key': pub_key
                                    }
                                }))

                        elif data['type'] == 'delete_account':
                            delete_user(username)
                            await websocket.send(json.dumps({
                                'type': 'account_deleted'
                            }))
                            break

                    except json.JSONDecodeError:
                        print(f"[!] Invalid JSON from {username}")
                    except Exception as e:
                        print(f"[!] Handler error: {e}")

        except ConnectionClosed:
            pass
        except Exception as e:
            print(f"[!] Client error ({username}): {e}")
        finally:
            if username:
                await self.unregister(username)

# ==================== ENTRY POINT ====================
async def main():
    """Initialize the database, start the HTTP server and run the WebSocket server."""
    init_db()

    local_ip = get_local_ip()

    print("=" * 70)
    print("SHADE MESSENGER SERVER (E2E ENCRYPTED)")
    print("=" * 70)
    print(f"WebSocket: ws://{local_ip}:{WS_PORT}")
    print(f"HTTP:      http://{local_ip}:{HTTP_PORT}")
    print("=" * 70)
    print("\nOpen in browser:")
    print(f"    http://localhost:{HTTP_PORT}")
    print(f"    http://{local_ip}:{HTTP_PORT}")
    print("\nFor other devices on the network:")
    print(f"    http://{local_ip}:{HTTP_PORT}")
    print("\n" + "=" * 70)
    print("E2E encryption: RSA-2048 + AES-256-GCM")
    print("SQL injection protection: parameterized queries")
    print("Server is running. Waiting for connections...")
    print("Press Ctrl+C to stop")
    print("=" * 70)

    # HTTP server runs in a separate thread
    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    await asyncio.sleep(1)

    try:
        webbrowser.open(f"http://localhost:{HTTP_PORT}")
    except:
        pass

    server = ShadeServer()
    async with serve(server.handle_client, HOST, WS_PORT):
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Server stopped")
    except Exception as e:
        print(f"\n[!] Error: {e}")#!/usr/bin/env python3
"""
Shade WebSocket Server + HTTP Server
End-to-end encrypted messenger (RSA + AES).
SQL injection protection via parameterized queries.
"""

import asyncio
import json
import sqlite3
import os
import socket
import webbrowser
import re
from datetime import datetime
from websockets.server import serve
from websockets.exceptions import ConnectionClosed
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading

# ==================== SERVER CONFIG ====================
HOST = '0.0.0.0'
WS_PORT = 8765
HTTP_PORT = 8000
DB_FILE = 'shade.db'

# ==================== INPUT VALIDATION / SQL INJECTION PROTECTION ====================
def sanitize_input(value):
    """Strip potentially dangerous SQL constructs from user input."""
    if value is None:
        return None
    dangerous_patterns = [';', '--', '/*', '*/', 'xp_', 'exec', 'union', 'select', 'insert', 'update', 'delete', 'drop', 'alter']
    cleaned = str(value)
    for pattern in dangerous_patterns:
        cleaned = cleaned.replace(pattern, '')
    cleaned = re.sub(r'[^a-zA-Z0-9@_\-. ]', '', cleaned)
    return cleaned

def validate_username(username):
    """Username must be 3-30 chars: letters, digits, _, -, ."""
    if not username:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_\-.]{3,30}$', username))

def validate_nickname(nickname):
    """Display name must be 2-50 chars (Latin/Cyrillic letters, digits, spaces, _-. )"""
    if not nickname:
        return False
    return bool(re.match(r'^[a-zA-Zа-яА-Я0-9_ \-.]{2,50}$', nickname))

def validate_password(password):
    """Password hash must be at least 6 characters long."""
    if not password:
        return False
    return len(password) >= 6

# ==================== LOCAL IP DETECTION ====================
def get_local_ip():
    """Return the machine's local network IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip.startswith('127.'):
                return "127.0.0.1"
            return ip
        except:
            return "127.0.0.1"

# ==================== DATABASE ====================
def init_db():
    """Create database tables if they do not exist yet."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            nickname TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT,
            created_at INTEGER NOT NULL,
            settings TEXT DEFAULT '{"hashEnabled": true}'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            delivered BOOLEAN DEFAULT 0,
            FOREIGN KEY (from_user) REFERENCES users(username),
            FOREIGN KEY (to_user) REFERENCES users(username)
        )
    ''')

    conn.commit()
    conn.close()
    print("[+] Database initialized")

def get_user(username):
    """Fetch a user record by username. Returns dict or None."""
    if not validate_username(username):
        return None

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT username, nickname, password_hash, public_key, settings FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            'username': row[0],
            'nickname': row[1],
            'password_hash': row[2],
            'public_key': row[3],
            'settings': json.loads(row[4])
        }
    return None

def create_user(username, nickname, password_hash, public_key=None):
    """Insert a new user. Returns True on success, False if the username is taken."""
    if not validate_username(username) or not validate_nickname(nickname):
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, nickname, password_hash, public_key, created_at, settings) VALUES (?, ?, ?, ?, ?, ?)',
            (username, nickname, password_hash, public_key, int(datetime.now().timestamp()), json.dumps({'hashEnabled': True}))
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def update_user(username, nickname, settings):
    """Update a user's nickname and settings."""
    if not validate_username(username) or not validate_nickname(nickname):
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET nickname = ?, settings = ? WHERE username = ?',
        (nickname, json.dumps(settings), username)
    )
    conn.commit()
    conn.close()
    return True

def update_public_key(username, public_key):
    """Replace the user's stored public key."""
    if not validate_username(username):
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET public_key = ? WHERE username = ?', (public_key, username))
    conn.commit()
    conn.close()
    return True

def update_password(username, password_hash):
    """Replace the user's password hash."""
    if not validate_username(username):
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?', (password_hash, username))
    conn.commit()
    conn.close()
    return True

def save_message(from_user, to_user, encrypted_content):
    """Persist an encrypted message to the database."""
    if not validate_username(from_user) or not validate_username(to_user):
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO messages (from_user, to_user, encrypted_content, timestamp) VALUES (?, ?, ?, ?)',
        (from_user, to_user, encrypted_content, int(datetime.now().timestamp()))
    )
    conn.commit()
    conn.close()
    return True

def get_messages_for_user(username):
    """Return all messages sent or received by the user, ordered by timestamp."""
    if not validate_username(username):
        return []

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, from_user, to_user, encrypted_content, timestamp, delivered
        FROM messages
        WHERE to_user = ? OR from_user = ?
        ORDER BY timestamp ASC
    ''', (username, username))
    rows = cursor.fetchall()
    conn.close()

    messages = []
    for row in rows:
        messages.append({
            'id': row[0],
            'from': row[1],
            'to': row[2],
            'content': row[3],
            'timestamp': row[4],
            'delivered': bool(row[5])
        })
    return messages

def mark_delivered(message_id):
    """Mark a message as delivered."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE messages SET delivered = 1 WHERE id = ?', (message_id,))
    conn.commit()
    conn.close()

def delete_user(username):
    """Delete a user and all messages associated with them."""
    if not validate_username(username):
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    cursor.execute('DELETE FROM messages WHERE from_user = ? OR to_user = ?', (username, username))
    conn.commit()
    conn.close()

def search_users(query, online_users=None):
    """Search users by username or nickname (substring match, case-insensitive on ASCII)."""
    clean_query = sanitize_input(query)
    if not clean_query or len(clean_query) < 2:
        return []

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT username, nickname, public_key
        FROM users
        WHERE username LIKE ? OR nickname LIKE ?
        LIMIT 20
    ''', (f'%{clean_query}%', f'%{clean_query}%'))

    rows = cursor.fetchall()
    conn.close()

    if online_users is None:
        online_users = []

    results = []
    for row in rows:
        results.append({
            'username': row[0],
            'nickname': row[1],
            'public_key': row[2],
            'online': row[0] in online_users
        })

    return results

def get_public_key(username):
    """Return the public key of a user, or None if not found."""
    if not validate_username(username):
        return None

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

# ==================== HTTP SERVER (static frontend) ====================
class CustomHTTPHandler(SimpleHTTPRequestHandler):
    """Serves the frontend directory and adds permissive CORS headers."""
    def __init__(self, *args, **kwargs):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        frontend_dir = os.path.join(base_dir, '..', 'frontend')
        super().__init__(*args, directory=frontend_dir, **kwargs)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def log_message(self, format, *args):
        pass  # Silence per-request HTTP logs

def start_http_server():
    """Run the HTTP server (blocking call, intended to run in a thread)."""
    httpd = HTTPServer(('0.0.0.0', HTTP_PORT), CustomHTTPHandler)
    httpd.serve_forever()

# ==================== WEBSOCKET SERVER ====================
class ShadeServer:
    """WebSocket server handling authentication, message routing and user search."""

    def __init__(self):
        self.clients = {}            # username -> websocket
        self.pending_messages = {}   # username -> list of queued messages (offline)

    async def register(self, websocket, username):
        """Register a connected client and flush any queued messages."""
        self.clients[username] = websocket

        # Deliver messages that arrived while the user was offline
        if username in self.pending_messages:
            for message in self.pending_messages[username]:
                await websocket.send(json.dumps({
                    'type': 'message',
                    'data': message
                }))
            del self.pending_messages[username]

        # Notify everyone else that this user came online
        await self.broadcast({
            'type': 'user_online',
            'data': {'username': username}
        }, exclude=[username])

        print(f"[+] {username} connected")

    async def unregister(self, username):
        """Remove a client and notify others that they went offline."""
        if username in self.clients:
            del self.clients[username]
            await self.broadcast({
                'type': 'user_offline',
                'data': {'username': username}
            })
            print(f"[-] {username} disconnected")

    async def broadcast(self, message, exclude=None):
        """Send a message to every connected client except those in `exclude`."""
        if exclude is None:
            exclude = []
        for username, websocket in self.clients.items():
            if username not in exclude:
                try:
                    await websocket.send(json.dumps(message))
                except:
                    pass

    async def send_to_user(self, username, message):
        """Deliver a message to a user, or queue it if they are offline."""
        if username in self.clients:
            try:
                await self.clients[username].send(json.dumps(message))
                return True
            except:
                return False
        else:
            if username not in self.pending_messages:
                self.pending_messages[username] = []
            self.pending_messages[username].append(message['data'])
            return False

    async def handle_client(self, websocket, path):
        """Per-connection handler: authenticate, then process incoming frames."""
        username = None

        try:
            # The first frame must be an authentication request
            auth_msg = await websocket.recv()
            data = json.loads(auth_msg)

            if data['type'] == 'auth':
                username = data['data']['username']
                password_hash = data['data']['password_hash']
                public_key = data['data'].get('public_key', None)

                if not validate_username(username) or not validate_password(password_hash):
                    await websocket.send(json.dumps({
                        'type': 'auth_error',
                        'data': {'message': 'Invalid credentials format'}
                    }))
                    return

                user = get_user(username)
                if user:
                    # Existing user: verify password
                    if user['password_hash'] != password_hash:
                        await websocket.send(json.dumps({
                            'type': 'auth_error',
                            'data': {'message': 'Invalid password'}
                        }))
                        return

                    # Rotate public key if the client supplied a new one
                    if public_key and user['public_key'] != public_key:
                        update_public_key(username, public_key)
                        user = get_user(username)
                else:
                    # New user: register
                    nickname = data['data'].get('nickname', username)
                    if not validate_nickname(nickname):
                        await websocket.send(json.dumps({
                            'type': 'auth_error',
                            'data': {'message': 'Invalid nickname format'}
                        }))
                        return

                    if not create_user(username, nickname, password_hash, public_key):
                        await websocket.send(json.dumps({
                            'type': 'auth_error',
                            'data': {'message': 'Failed to create user'}
                        }))
                        return
                    user = get_user(username)

                await websocket.send(json.dumps({
                    'type': 'auth_success',
                    'data': {
                        'username': username,
                        'nickname': user['nickname'],
                        'public_key': user['public_key'],
                        'settings': user['settings']
                    }
                }))

                # Send message history
                messages = get_messages_for_user(username)
                if messages:
                    await websocket.send(json.dumps({
                        'type': 'history',
                        'data': messages
                    }))

                await self.register(websocket, username)

                # Main message loop
                async for message in websocket:
                    try:
                        data = json.loads(message)

                        if data['type'] == 'message':
                            to_user = data['data']['to']
                            encrypted_content = data['data']['content']

                            if not validate_username(to_user):
                                continue

                            save_message(username, to_user, encrypted_content)

                            await self.send_to_user(to_user, {
                                'type': 'message',
                                'data': {
                                    'id': 0,
                                    'from': username,
                                    'to': to_user,
                                    'content': encrypted_content,
                                    'timestamp': int(datetime.now().timestamp()),
                                    'delivered': False,
                                    'isFile': data['data'].get('isFile', False),
                                    'fileName': data['data'].get('fileName', None),
                                    'fileSize': data['data'].get('fileSize', None),
                                    'fileType': data['data'].get('fileType', None)
                                }
                            })

                        elif data['type'] == 'delivered':
                            message_id = data['data']['message_id']
                            if isinstance(message_id, int):
                                mark_delivered(message_id)

                        elif data['type'] == 'profile_update':
                            nickname = data['data'].get('nickname')
                            settings = data['data'].get('settings')
                            if nickname and settings and validate_nickname(nickname):
                                update_user(username, nickname, settings)
                                user = get_user(username)
                                await websocket.send(json.dumps({
                                    'type': 'profile_updated',
                                    'data': {
                                        'nickname': user['nickname'],
                                        'settings': user['settings']
                                    }
                                }))

                        elif data['type'] == 'search_users':
                            query = data['data'].get('query', '')
                            if len(query) >= 2:
                                online_users = list(self.clients.keys())
                                results = search_users(query, online_users)
                                await websocket.send(json.dumps({
                                    'type': 'search_results',
                                    'data': results
                                }))

                        elif data['type'] == 'get_public_key':
                            target = data['data'].get('username')
                            if target and validate_username(target):
                                pub_key = get_public_key(target)
                                await websocket.send(json.dumps({
                                    'type': 'public_key_response',
                                    'data': {
                                        'username': target,
                                        'public_key': pub_key
                                    }
                                }))

                        elif data['type'] == 'delete_account':
                            delete_user(username)
                            await websocket.send(json.dumps({
                                'type': 'account_deleted'
                            }))
                            break

                    except json.JSONDecodeError:
                        print(f"[!] Invalid JSON from {username}")
                    except Exception as e:
                        print(f"[!] Handler error: {e}")

        except ConnectionClosed:
            pass
        except Exception as e:
            print(f"[!] Client error ({username}): {e}")
        finally:
            if username:
                await self.unregister(username)

# ==================== ENTRY POINT ====================
async def main():
    """Initialize the database, start the HTTP server and run the WebSocket server."""
    init_db()

    local_ip = get_local_ip()

    print("=" * 70)
    print("SHADE MESSENGER SERVER (E2E ENCRYPTED)")
    print("=" * 70)
    print(f"WebSocket: ws://{local_ip}:{WS_PORT}")
    print(f"HTTP:      http://{local_ip}:{HTTP_PORT}")
    print("=" * 70)
    print("\nOpen in browser:")
    print(f"    http://localhost:{HTTP_PORT}")
    print(f"    http://{local_ip}:{HTTP_PORT}")
    print("\nFor other devices on the network:")
    print(f"    http://{local_ip}:{HTTP_PORT}")
    print("\n" + "=" * 70)
    print("E2E encryption: RSA-2048 + AES-256-GCM")
    print("SQL injection protection: parameterized queries")
    print("Server is running. Waiting for connections...")
    print("Press Ctrl+C to stop")
    print("=" * 70)

    # HTTP server runs in a separate thread
    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    await asyncio.sleep(1)

    try:
        webbrowser.open(f"http://localhost:{HTTP_PORT}")
    except:
        pass

    server = ShadeServer()
    async with serve(server.handle_client, HOST, WS_PORT):
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Server stopped")
    except Exception as e:
        print(f"\n[!] Error: {e}")
