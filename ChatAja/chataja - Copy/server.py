# nama file: server.py
import socket
import threading
import json
import hashlib
import re
import mysql.connector
from mysql.connector import Error
import string
import random
import os
import base64

# --- PENGATURAN SERVER ---
SERVER_UPLOADS_DIR = "server_uploads"
MAX_FILE_SIZE = 50 * 1024 * 1024 # Batas ukuran file 50MB
if not os.path.exists(SERVER_UPLOADS_DIR):
    os.makedirs(SERVER_UPLOADS_DIR)

# --- BAGIAN ENKRIPSI / CIPHER (Substitution Cipher) ---
ALPHABET = string.printable
key_list = list(ALPHABET)
random.seed(42) 
random.shuffle(key_list)
KEY = "".join(key_list)
ENCRYPT_MAP = str.maketrans(ALPHABET, KEY)
DECRYPT_MAP = str.maketrans(KEY, ALPHABET)

def encrypt(message):
    """Enkripsi pesan sebelum disimpan ke database."""
    return message.translate(ENCRYPT_MAP)

def decrypt(message):
    """Dekripsi pesan dari database sebelum dikirim ke client."""
    return message.translate(DECRYPT_MAP)

# --- KONFIGURASI DATABASE MYSQL ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'encrypted_chat_app'
}
clients = {}  # {username: socket}
file_transfers = {} # {file_id: {info}}

# --- FUNGSI-FUNGSI DATABASE & LOGIKA ---
def get_db_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        print(f"DB Error: {e}")
        return None

def _hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def is_password_strong(password):
    return len(password) >= 8

def db_add_user(username, password):
    if not is_password_strong(password):
        return False, "Password lemah! Harus minimal 8 karakter."
    conn = get_db_connection()
    if not conn: return False, "Server database error."
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, _hash_password(password)))
        conn.commit()
        return True, "Registrasi berhasil."
    except Error:
        return False, "Username sudah ada."
    finally:
        cursor.close()
        conn.close()

def db_check_credentials(username, password):
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user and user['password_hash'] == _hash_password(password)

def db_log_message(sender, recipient, msg_type, content):
    conn = get_db_connection()
    if not conn: return
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender_username, recipient_name, message_type, content) VALUES (%s, %s, %s, %s)",
                   (sender, recipient, msg_type, content))
    conn.commit()
    cursor.close()
    conn.close()

def db_get_chat_history(user1, recipient):
    conn = get_db_connection()
    if not conn: return []
    cursor = conn.cursor(dictionary=True)
    if recipient.startswith("Grup:"):
        query = "SELECT sender_username, message_type, content, timestamp FROM messages WHERE recipient_name = %s ORDER BY timestamp ASC"
        cursor.execute(query, (recipient,))
    else:
        query = """
            SELECT sender_username, recipient_name, message_type, content, timestamp 
            FROM messages WHERE (sender_username = %s AND recipient_name = %s) 
            OR (sender_username = %s AND recipient_name = %s) ORDER BY timestamp ASC
        """
        cursor.execute(query, (user1, recipient, recipient, user1))
    history = cursor.fetchall()
    cursor.close()
    conn.close()
    return history

def db_add_friend(user, friend):
    conn = get_db_connection()
    if not conn: return False, "Server database error."
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (friend,))
    if cursor.fetchone()[0] == 0 or user == friend:
        return False, "User tidak ditemukan atau tidak valid."
    cursor.execute("SELECT status FROM friendships WHERE (user_username = %s AND friend_username = %s) OR (user_username = %s AND friend_username = %s)", (user, friend, friend, user))
    if cursor.fetchone():
        return False, "Permintaan sudah dikirim atau sudah berteman."
    cursor.execute("INSERT INTO friendships (user_username, friend_username, status) VALUES (%s, %s, 'pending')", (user, friend))
    conn.commit()
    cursor.close()
    conn.close()
    return True, f"Permintaan teman ke {friend} terkirim."

def db_accept_friend(user, friend):
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE friendships SET status = 'accepted' WHERE user_username = %s AND friend_username = %s AND status = 'pending'", (friend, user))
        if cursor.rowcount == 0: return False
        cursor.execute("INSERT INTO friendships (user_username, friend_username, status) VALUES (%s, %s, 'accepted')", (user, friend))
        conn.commit()
        return True
    except Error:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def db_get_friends(username):
    conn = get_db_connection()
    if not conn: return []
    cursor = conn.cursor()
    cursor.execute("SELECT friend_username FROM friendships WHERE user_username = %s AND status = 'accepted'", (username,))
    friends = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return friends

def db_create_group(group_name, owner):
    conn = get_db_connection()
    if not conn: return False
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO groups (group_name, owner_username) VALUES (%s, %s)", (group_name, owner))
        group_id = cursor.lastrowid
        cursor.execute("INSERT INTO group_members (group_id, username) VALUES (%s, %s)", (group_id, owner))
        conn.commit()
        return True
    except Error:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def db_add_user_to_group(group_name, user_to_add, requester):
    conn = get_db_connection()
    if not conn: return "DB Error"
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT owner_username, id FROM groups WHERE group_name = %s", (f"Grup:{group_name}",))
        group = cursor.fetchone()
        if not group or group['owner_username'] != requester: return "Anda bukan admin grup ini."
        cursor.execute("SELECT id FROM users WHERE username = %s", (user_to_add,))
        if not cursor.fetchone(): return f"User {user_to_add} tidak ditemukan."
        group_id = group['id']
        cursor.execute("INSERT INTO group_members (group_id, username) VALUES (%s, %s)", (group_id, user_to_add))
        conn.commit()
        return f"Berhasil menambahkan {user_to_add} ke grup {group_name}."
    except Error:
        conn.rollback()
        return "Gagal menambahkan user, mungkin sudah menjadi anggota."
    finally:
        cursor.close()
        conn.close()

def db_get_group_members_by_name(full_group_name):
    conn = get_db_connection()
    if not conn: return []
    cursor = conn.cursor(dictionary=True)
    query = "SELECT gm.username FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE g.group_name = %s"
    cursor.execute(query, (full_group_name,))
    members = [row['username'] for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return members

def db_get_user_groups(username):
    conn = get_db_connection()
    if not conn: return []
    cursor = conn.cursor()
    query = "SELECT g.group_name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = %s"
    cursor.execute(query, (username,))
    groups = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return groups

# --- LOGIKA SERVER UTAMA ---
def broadcast_online_list():
    online_users = list(clients.keys())
    for sock in clients.values():
        try:
            sock.sendall(json.dumps({"type": "online_users_list", "users": online_users}).encode('utf-8'))
        except (ConnectionResetError, BrokenPipeError):
            continue

def send_to_client(username, data, temp_conn=None):
    target_conn = clients.get(username) or temp_conn
    if target_conn:
        try:
            target_conn.sendall(json.dumps(data).encode('utf-8'))
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

def server_file_sender(file_info, requester_username):
    """Mengirim file dari server ke client yang meminta."""
    filepath = file_info['server_filepath']
    filename = file_info['filename']
    file_id = file_info['file_id']
    
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                send_to_client(requester_username, {"type": "file_data", "file_id": file_id, "chunk_b64": base64.b64encode(chunk).decode('utf-8')})
        send_to_client(requester_username, {"type": "file_end", "file_id": file_id, "filename": filename})
        print(f"Berhasil mengirim file '{filename}' ke {requester_username}")
    except Exception as e:
        print(f"Error saat mengirim file {file_id} ke {requester_username}: {e}")
        send_to_client(requester_username, {"type": "notification", "content": f"Gagal mengunduh file '{filename}'."})

def handle_client(conn):
    username = None
    authenticated = False
    try:
        buffer = b""
        while True:
            data = conn.recv(16384)
            if not data: break
            
            buffer += data
            while True:
                try:
                    message, index = json.JSONDecoder().raw_decode(buffer.decode('utf-8', errors='ignore'))
                    buffer = buffer[index:].lstrip()
                except (json.JSONDecodeError, UnicodeDecodeError):
                    break 

                msg_type = message.get("type")

                if not authenticated:
                    if msg_type == 'login':
                        req_user = message['username']
                        if req_user in clients:
                            send_to_client(None, {"type": "login_response", "success": False, "reason": "User sudah login."}, temp_conn=conn)
                            continue
                        if db_check_credentials(req_user, message['password']):
                            username = req_user
                            authenticated = True
                            clients[username] = conn
                            send_to_client(username, {"type": "login_response", "success": True, "username": username, "online_users": list(clients.keys())})
                            broadcast_online_list()
                            print(f"[LOGIN] {username} online. Total: {len(clients)}")
                        else:
                            send_to_client(None, {"type": "login_response", "success": False, "reason": "Username atau password salah."}, temp_conn=conn)
                    elif msg_type == 'register':
                        success, reason = db_add_user(message['username'], message['password'])
                        send_to_client(None, {"type": "register_response", "success": success, "reason": reason}, temp_conn=conn)
                    continue
                
                sender = message.get("sender")

                if msg_type == "logout":
                    break 

                elif msg_type == "get_chat_history":
                    history = db_get_chat_history(sender, message['recipient'])
                    for row in history:
                        if row.get('message_type') == 'text' and row.get('content'):
                            row['content'] = decrypt(row['content'])
                        if isinstance(row.get('timestamp'), object):
                            row['timestamp'] = row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    send_to_client(sender, {"type": "chat_history", "history": history, "recipient": message['recipient']})

                elif msg_type == "initiate_upload":
                    filesize = message.get('filesize', 0)
                    if filesize > MAX_FILE_SIZE:
                        send_to_client(sender, {"type": "notification", "content": f"Gagal: Ukuran file {filesize/(1024*1024):.2f}MB melebihi batas 50MB."})
                        continue
                    file_id = message['file_id']
                    filepath = os.path.join(SERVER_UPLOADS_DIR, file_id)
                    message['server_filepath'] = filepath
                    try:
                        message['file_handle'] = open(filepath, 'wb')
                        file_transfers[file_id] = message
                        send_to_client(sender, {"type": "upload_approved", "file_id": file_id})
                    except Exception as e:
                        print(f"Gagal membuat file untuk diunggah: {e}")

                elif msg_type == "file_data":
                    file_id = message['file_id']
                    if file_id in file_transfers and file_transfers[file_id].get('file_handle'):
                        chunk = base64.b64decode(message['chunk_b64'])
                        file_transfers[file_id]['file_handle'].write(chunk)

                elif msg_type == "file_end":
                    file_id = message['file_id']
                    if file_id in file_transfers:
                        info = file_transfers[file_id]
                        if 'file_handle' in info and not info['file_handle'].closed:
                            info['file_handle'].close()
                        
                        file_info_for_db = json.dumps({
                            "filename": info["filename"], "filesize": info["filesize"],
                            "file_id": file_id, "thumbnail": info.get("thumbnail")
                        })
                        db_log_message(info['sender'], info['recipient'], 'file_offer', file_info_for_db)
                        
                        offer_to_send = {
                            "type": "file_offer", "sender": info['sender'], "recipient": info['recipient'],
                            "file_id": file_id, "filename": info['filename'],
                            "filesize": info['filesize'], "thumbnail": info.get("thumbnail")
                        }
                        send_to_client(info['recipient'], offer_to_send)
                        print(f"File '{info['filename']}' (ID: {file_id}) diterima, penawaran dikirim.")

                elif msg_type == "accept_file_offer":
                    file_id = message['file_id']
                    requester = message['requester']
                    file_info = file_transfers.get(file_id)
                    
                    if not file_info:
                        server_filepath = os.path.join(SERVER_UPLOADS_DIR, file_id)
                        if os.path.exists(server_filepath):
                            file_info = {
                                'server_filepath': server_filepath,
                                'filename': message.get('filename', file_id),
                                'file_id': file_id
                            }
                            print(f"File '{file_id}' ditemukan di disk untuk {requester}.")
                        else:
                             send_to_client(requester, {"type": "notification", "content": "Download gagal: file tidak ditemukan."})
                             continue
                    
                    threading.Thread(target=server_file_sender, args=(file_info, requester), daemon=True).start()

                elif msg_type == "private_message":
                    recipient, content = message["recipient"], message["content"]
                    encrypted_content = encrypt(content)
                    db_log_message(sender, recipient, 'text', encrypted_content)
                    if recipient.startswith("Grup:"):
                        members = db_get_group_members_by_name(recipient)
                        for member in members:
                            if member != sender: send_to_client(member, message)
                    else:
                        send_to_client(recipient, message)
                
                elif msg_type == "get_friends_list":
                    send_to_client(sender, {"type": "friends_list", "friends": db_get_friends(sender)})
                elif msg_type == "get_my_groups":
                    send_to_client(sender, {"type": "my_groups_list", "groups": db_get_user_groups(sender)})
                elif msg_type == "add_friend":
                    success, reason = db_add_friend(sender, message["friend_username"])
                    send_to_client(sender, {"type":"notification", "content": reason})
                    if success: send_to_client(message["friend_username"], {"type": "friend_request", "from": sender})
                elif msg_type == "accept_friend":
                    friend_name = message["friend_username"]
                    if db_accept_friend(sender, friend_name):
                        send_to_client(sender, {"type":"notification", "content":f"Anda sekarang berteman dengan {friend_name}."})
                        send_to_client(friend_name, {"type":"notification", "content":f"{sender} menerima permintaan Anda."})
                        send_to_client(sender, {"type": "friends_list", "friends": db_get_friends(sender)})
                        send_to_client(friend_name, {"type": "friends_list", "friends": db_get_friends(friend_name)})
                elif msg_type == "create_group":
                    if db_create_group(f"Grup:{message['group_name']}", sender):
                        send_to_client(sender, {"type": "notification", "content": f"Grup '{message['group_name']}' berhasil dibuat."})
                        send_to_client(sender, {"type": "my_groups_list", "groups": db_get_user_groups(sender)})
                    else:
                        send_to_client(sender, {"type": "notification", "content": "Gagal, nama grup mungkin sudah ada."})
                elif msg_type == "add_to_group":
                    result = db_add_user_to_group(message['group_name'], message['user_to_add'], sender)
                    send_to_client(sender, {"type": "notification", "content": result})
                    if "Berhasil" in result:
                        send_to_client(message['user_to_add'], {"type": "notification", "content": f"Anda ditambahkan ke grup '{message['group_name']}'."})
                        send_to_client(message['user_to_add'], {"type": "my_groups_list", "groups": db_get_user_groups(message['user_to_add'])})

    except (json.JSONDecodeError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        if username and username in clients:
            del clients[username]
            print(f"[LOGOUT] {username} offline. Sisa: {len(clients)}")
            broadcast_online_list()
        
        for file_id, info in list(file_transfers.items()):
            if info.get('sender') == username and 'file_handle' in info and not info['file_handle'].closed:
                info['file_handle'].close()
                if os.path.exists(info['server_filepath']):
                    os.remove(info['server_filepath'])
                del file_transfers[file_id]
                print(f"Dibersihkan transfer tidak lengkap {file_id} dari {username}")
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 65432))
    server.listen(10)
    print(f"[SERVER AKTIF] Port: 65432, Batas file: {MAX_FILE_SIZE/(1024*1024):.0f}MB")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    start_server()