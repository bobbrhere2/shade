#!/usr/bin/env python3
"""
Shade WebSocket Server + HTTP Server
Защищённый мессенджер с E2E шифрованием (RSA + AES)
ЗАЩИТА ОТ SQL-ИНЪЕКЦИЙ через параметризованные запросы
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

# ==================== КОНФИГ ====================
HOST = '0.0.0.0'
WS_PORT = 8765
HTTP_PORT = 8000
DB_FILE = 'shade.db'

# ==================== ЗАЩИТА ОТ SQL-ИНЪЕКЦИЙ ====================
def sanitize_input(value):
    if value is None:
        return None
    dangerous = [';', '--', '/*', '*/', 'xp_', 'exec', 'union', 'select', 'insert', 'update', 'delete', 'drop', 'alter']
    cleaned = str(value)
    for item in dangerous:
        cleaned = cleaned.replace(item, '')
    cleaned = re.sub(r'[^a-zA-Z0-9@_\-. ]', '', cleaned)
    return cleaned

def validate_username(username):
    if not username:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_\-.]{3,30}$', username))

def validate_nickname(nickname):
    if not nickname:
        return False
    return bool(re.match(r'^[a-zA-Zа-яА-Я0-9_ \-.]{2,50}$', nickname))

def validate_password(password):
    if not password:
        return False
    return len(password) >= 6

# ==================== ПОЛУЧЕНИЕ IP ====================
def get_local_ip():
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

# ==================== БАЗА ДАННЫХ ====================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            nickname TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT,
            created_at INTEGER NOT NULL,
            settings TEXT DEFAULT '{"hashEnabled": true}'
        )
    ''')
    
    c.execute('''
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
    print("[+] База данных инициализирована")

def get_user(username):
    if not validate_username(username):
        return None
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT username, nickname, password_hash, public_key, settings FROM users WHERE username = ?', (username,))
    row = c.fetchone()
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
    if not validate_username(username) or not validate_nickname(nickname):
        return False
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute(
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
    if not validate_username(username) or not validate_nickname(nickname):
        return False
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        'UPDATE users SET nickname = ?, settings = ? WHERE username = ?',
        (nickname, json.dumps(settings), username)
    )
    conn.commit()
    conn.close()
    return True

def update_public_key(username, public_key):
    if not validate_username(username):
        return False
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE users SET public_key = ? WHERE username = ?', (public_key, username))
    conn.commit()
    conn.close()
    return True

def update_password(username, password_hash):
    if not validate_username(username):
        return False
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE users SET password_hash = ? WHERE username = ?', (password_hash, username))
    conn.commit()
    conn.close()
    return True

def save_message(from_user, to_user, encrypted_content):
    if not validate_username(from_user) or not validate_username(to_user):
        return False
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        'INSERT INTO messages (from_user, to_user, encrypted_content, timestamp) VALUES (?, ?, ?, ?)',
        (from_user, to_user, encrypted_content, int(datetime.now().timestamp()))
    )
    conn.commit()
    conn.close()
    return True

def get_messages_for_user(username):
    if not validate_username(username):
        return []
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        SELECT id, from_user, to_user, encrypted_content, timestamp, delivered 
        FROM messages 
        WHERE to_user = ? OR from_user = ?
        ORDER BY timestamp ASC
    ''', (username, username))
    rows = c.fetchall()
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
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE messages SET delivered = 1 WHERE id = ?', (message_id,))
    conn.commit()
    conn.close()

def delete_user(username):
    if not validate_username(username):
        return
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE username = ?', (username,))
    c.execute('DELETE FROM messages WHERE from_user = ? OR to_user = ?', (username, username))
    conn.commit()
    conn.close()

def search_users(query, online_users=None):
    clean_query = sanitize_input(query)
    if not clean_query or len(clean_query) < 2:
        return []
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        SELECT username, nickname, public_key 
        FROM users 
        WHERE username LIKE ? OR nickname LIKE ?
        LIMIT 20
    ''', (f'%{clean_query}%', f'%{clean_query}%'))
    
    rows = c.fetchall()
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
    if not validate_username(username):
        return None
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT public_key FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

# ==================== HTTP СЕРВЕР ====================
class CustomHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        import os
        base_dir = os.path.dirname(os.path.abspath(__file__))
        frontend_dir = os.path.join(base_dir, '..', 'frontend')
        super().__init__(*args, directory=frontend_dir, **kwargs)
    
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()
    
    def log_message(self, format, *args):
        pass

def start_http_server():
    httpd = HTTPServer(('0.0.0.0', HTTP_PORT), CustomHTTPHandler)
    httpd.serve_forever()

# ==================== ВЕБСОКЕТ СЕРВЕР ====================
class ShadeServer:
    def __init__(self):
        self.clients = {}
        self.pending_messages = {}
    
    async def register(self, websocket, username):
        self.clients[username] = websocket
        
        if username in self.pending_messages:
            for msg in self.pending_messages[username]:
                await websocket.send(json.dumps({
                    'type': 'message',
                    'data': msg
                }))
            del self.pending_messages[username]
        
        await self.broadcast({
            'type': 'user_online',
            'data': {'username': username}
        }, exclude=[username])
        
        print(f"[+] {username} подключился")
    
    async def unregister(self, username):
        if username in self.clients:
            del self.clients[username]
            await self.broadcast({
                'type': 'user_offline',
                'data': {'username': username}
            })
            print(f"[-] {username} отключился")
    
    async def broadcast(self, message, exclude=None):
        if exclude is None:
            exclude = []
        for username, ws in self.clients.items():
            if username not in exclude:
                try:
                    await ws.send(json.dumps(message))
                except:
                    pass
    
    async def send_to_user(self, username, message):
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
        username = None
        
        try:
            auth_msg = await websocket.recv()
            data = json.loads(auth_msg)
            
            if data['type'] == 'auth':
                username = data['data']['username']
                password_hash = data['data']['password_hash']
                public_key = data['data'].get('public_key', None)
                
                if not validate_username(username) or not validate_password(password_hash):
                    await websocket.send(json.dumps({
                        'type': 'auth_error',
                        'data': {'message': 'Неверный формат данных'}
                    }))
                    return
                
                user = get_user(username)
                if user:
                    if user['password_hash'] != password_hash:
                        await websocket.send(json.dumps({
                            'type': 'auth_error',
                            'data': {'message': 'Неверный пароль'}
                        }))
                        return
                    
                    if public_key and user['public_key'] != public_key:
                        update_public_key(username, public_key)
                        user = get_user(username)
                else:
                    nickname = data['data'].get('nickname', username)
                    if not validate_nickname(nickname):
                        await websocket.send(json.dumps({
                            'type': 'auth_error',
                            'data': {'message': 'Неверный формат ника'}
                        }))
                        return
                    
                    if not create_user(username, nickname, password_hash, public_key):
                        await websocket.send(json.dumps({
                            'type': 'auth_error',
                            'data': {'message': 'Ошибка создания пользователя'}
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
                
                messages = get_messages_for_user(username)
                if messages:
                    await websocket.send(json.dumps({
                        'type': 'history',
                        'data': messages
                    }))
                
                await self.register(websocket, username)
                
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
                            if nickname and settings:
                                if validate_nickname(nickname):
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
                        print(f"[!] Невалидный JSON от {username}")
                    except Exception as e:
                        print(f"[!] Ошибка обработки: {e}")
                
        except ConnectionClosed:
            pass
        except Exception as e:
            print(f"[!] Ошибка клиента {username}: {e}")
        finally:
            if username:
                await self.unregister(username)

# ==================== ЗАПУСК ====================
async def main():
    init_db()
    
    local_ip = get_local_ip()
    
    print("=" * 70)
    print("SHADE MESSENGER SERVER (E2E ENCRYPTED)")
    print("ЗАЩИТА ОТ SQL-ИНЪЕКЦИЙ ВКЛЮЧЕНА")
    print("=" * 70)
    print(f"WebSocket: ws://{local_ip}:{WS_PORT}")
    print(f"HTTP:      http://{local_ip}:{HTTP_PORT}")
    print("=" * 70)
    print("\nОТКРОЙ В БРАУЗЕРЕ:")
    print(f"    http://localhost:{HTTP_PORT}")
    print(f"   http://{local_ip}:{HTTP_PORT}")
    print("\nДЛЯ ДРУГИХ УСТРОЙСТВ В СЕТИ:")
    print(f"    http://{local_ip}:{HTTP_PORT}")
    print("\n" + "=" * 70)
    print("E2E ШИФРОВАНИЕ: RSA-2048 + AES-256-GCM")
    print("ЗАЩИТА ОТ SQL-ИНЪЕКЦИЙ: ПАРАМЕТРИЗОВАННЫЕ ЗАПРОСЫ")
    print("Сервер запущен. Ожидание подключений...")
    print("Нажмите Ctrl+C для остановки")
    print("=" * 70)
    
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
        print("\n[!] Сервер остановлен")
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")