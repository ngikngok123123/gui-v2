import socket
import threading
import mysql.connector
from datetime import datetime
import hashlib # Untuk hashing password

# --- Konfigurasi Database ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root', # Ganti dengan username MySQL Anda
    'password': '', # Ganti dengan password MySQL Anda
    'database': 'encrypted_chat_app' # Ganti dengan nama database Anda
}

# --- Konfigurasi Server ---
HOST = '192.168.56.1' # Ganti dengan IP Address server Anda (IP komputer yang menjalankan server ini)
PORT = 12345

# --- Kunci Substitution Cipher (Harus sama dengan di klien) ---
ENCRYPTION_KEY = {
    'A': 'Z', 'B': 'Y', 'C': 'X', 'D': 'W', 'E': 'V', 'F': 'U', 'G': 'T', 'H': 'S', 'I': 'R', 'J': 'Q',
    'K': 'P', 'L': 'O', 'M': 'N', 'N': 'M', 'O': 'L', 'P': 'K', 'Q': 'J', 'R': 'I', 'S': 'H', 'T': 'G',
    'U': 'F', 'V': 'E', 'W': 'D', 'X': 'C', 'Y': 'B', 'Z': 'A',
    'a': 'z', 'b': 'y', 'c': 'x', 'd': 'w', 'e': 'v', 'f': 'u', 'g': 't', 'h': 's', 'i': 'r', 'j': 'q',
    'k': 'p', 'l': 'o', 'm': 'n', 'n': 'm', 'o': 'l', 'p': 'k', 'q': 'j', 'r': 'i', 's': 'h', 't': 'g',
    'u': 'f', 'v': 'e', 'w': 'd', 'x': 'c', 'y': 'b', 'z': 'a',
    '0': '9', '1': '8', '2': '7', '3': '6', '4': '5', '5': '4', '6': '3', '7': '2', '8': '1', '9': '0',
    '!': '@', '@': '!', '#': '$', '$': '#', '%': '^', '^': '%', '&': '*', '*': '&', '(': ')', ')': '(',
    '-': '+', '+': '-', '=': '_', '_': '=', '[': ']', ']': '[', '{': '}', '}': '{', ';': ':', ':': ';',
    "'": '"', '"': "'", '<': '>', '>': '<', ',': '.', '.': ',', '/': '?', '?': '/', '`': '~', '~': '`',
    ' ': ' ' # Spasi tetap spasi
}

# Inisialisasi Kunci Dekripsi (kebalikan dari ENCRYPTION_KEY)
DECRYPTION_KEY = {v: k for k, v in ENCRYPTION_KEY.items()}

# --- Fungsi Enkripsi dan Dekripsi ---
def encrypt(text):
    encrypted_text = ""
    for char in text:
        encrypted_text += ENCRYPTION_KEY.get(char, char)
    return encrypted_text

def decrypt(text):
    decrypted_text = ""
    for char in text:
        decrypted_text += DECRYPTION_KEY.get(char, char)
    return decrypted_text

# --- Variabel Global Server ---
clients = {} # {username: client_socket}
logged_in_users_id = {} # {username: user_id}
user_id_counter = 0 # Untuk memberikan ID unik ke setiap user yang login

# --- Fungsi Database ---
def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        # print(f"Error: {err}") # Dihilangkan dari log
        return None

def create_users_table():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            # print("Tabel 'users' dipastikan ada.") # Dihilangkan dari log
        except mysql.connector.Error as err:
            # print(f"Error creating users table: {err}") # Dihilangkan dari log
            pass # Lewati error tanpa menampilkan
        finally:
            cursor.close()
            conn.close()

def create_messages_table(): # Menggunakan struktur yang lebih generik untuk mendukung private/group
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    sender_id INT NOT NULL,
                    receiver_id INT NULL, -- NULL jika pesan grup
                    group_id INT NULL, -- NULL jika pesan pribadi
                    message_content TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
                    CHECK (receiver_id IS NOT NULL OR group_id IS NOT NULL)
                )
            """)
            conn.commit()
            # print("Tabel 'messages' dipastikan ada.") # Dihilangkan dari log
        except mysql.connector.Error as err:
            # print(f"Error creating messages table: {err}") # Dihilangkan dari log
            pass
        finally:
            cursor.close()
            conn.close()

def create_friendships_table():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS friendships (
                    user_id1 INT NOT NULL,
                    user_id2 INT NOT NULL,
                    status ENUM('pending', 'accepted', 'blocked') DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id1, user_id2),
                    FOREIGN KEY (user_id1) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id2) REFERENCES users(id) ON DELETE CASCADE,
                    CHECK (user_id1 < user_id2)
                )
            """)
            conn.commit()
            # print("Tabel 'friendships' dipastikan ada.") # Dihilangkan dari log
        except mysql.connector.Error as err:
            # print(f"Error creating friendships table: {err}") # Dihilangkan dari log
            pass
        finally:
            cursor.close()
            conn.close()

def create_groups_table():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS groups (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    group_name VARCHAR(255) UNIQUE NOT NULL,
                    created_by INT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            conn.commit()
            # print("Tabel 'groups' dipastikan ada.") # Dihilangkan dari log
        except mysql.connector.Error as err:
            # print(f"Error creating groups table: {err}") # Dihilangkan dari log
            pass
        finally:
            cursor.close()
            conn.close()

def create_group_members_table():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id INT NOT NULL,
                    user_id INT NOT NULL,
                    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (group_id, user_id),
                    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            conn.commit()
            # print("Tabel 'group_members' dipastikan ada.") # Dihilangkan dari log
        except mysql.connector.Error as err:
            # print(f"Error creating group_members table: {err}") # Dihilangkan dari log
            pass
        finally:
            cursor.close()
            conn.close()

def get_user_id(username):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
            return result[0] if result else None
        except mysql.connector.Error as err:
            # print(f"Error getting user ID: {err}") # Dihilangkan dari log
            return None
        finally:
            cursor.close()
            conn.close()

def get_username_by_id(user_id):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else None
        except mysql.connector.Error as err:
            # print(f"Error getting username by ID: {err}") # Dihilangkan dari log
            return None
        finally:
            cursor.close()
            conn.close()

def register_user(username, password_hash):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return "USERNAME_TAKEN"
            
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
            conn.commit()
            return "REGISTER_SUCCESS"
        except mysql.connector.Error as err:
            # print(f"Error registering user: {err}") # Dihilangkan dari log
            return "REGISTER_FAILED"
        finally:
            cursor.close()
            conn.close()

def authenticate_user(username, password_hash):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
            if result and result[0] == password_hash:
                return "LOGIN_SUCCESS"
            else:
                return "LOGIN_FAILED"
        except mysql.connector.Error as err:
            # print(f"Error authenticating user: {err}") # Dihilangkan dari log
            return "LOGIN_FAILED"
        finally:
            cursor.close()
            conn.close()

def delete_user_from_db(username, password_hash):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            user_id_to_delete = get_user_id(username)
            if not user_id_to_delete:
                return "DELETE_FAILED_AUTH" # User not found
                
            cursor.execute("SELECT password_hash FROM users WHERE id = %s", (user_id_to_delete,))
            result = cursor.fetchone()
            if not result or result[0] != password_hash:
                return "DELETE_FAILED_AUTH" 

            # Delete related data first (messages, group_members, friendships)
            cursor.execute("DELETE FROM messages WHERE sender_id = %s OR receiver_id = %s", (user_id_to_delete, user_id_to_delete))
            cursor.execute("DELETE FROM group_members WHERE user_id = %s", (user_id_to_delete,))
            cursor.execute("DELETE FROM friendships WHERE user_id1 = %s OR user_id2 = %s", (user_id_to_delete, user_id_to_delete))
            
            # Delete groups created by this user
            cursor.execute("DELETE FROM groups WHERE created_by = %s", (user_id_to_delete,))

            cursor.execute("DELETE FROM users WHERE id = %s", (user_id_to_delete,))
            conn.commit()
            return "DELETE_SUCCESS"
        except mysql.connector.Error as err:
            # print(f"Error deleting user: {err}") # Dihilangkan dari log
            return "DELETE_FAILED_DB"
        finally:
            cursor.close()
            conn.close()

def save_message(sender_username, message_content, receiver_username=None, group_name=None):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            sender_id = get_user_id(sender_username)
            receiver_id = get_user_id(receiver_username) if receiver_username else None
            group_id = get_group_id(group_name) if group_name else None

            if not sender_id:
                # print(f"Error: Sender '{sender_username}' not found.") # Dihilangkan dari log
                return

            if receiver_username and not receiver_id:
                # print(f"Error: Receiver '{receiver_username}' not found.") # Dihilangkan dari log
                return
            
            if group_name and not group_id:
                # print(f"Error: Group '{group_name}' not found.") # Dihilangkan dari log
                return

            cursor.execute("INSERT INTO messages (sender_id, receiver_id, group_id, message_content) VALUES (%s, %s, %s, %s)",
                           (sender_id, receiver_id, group_id, message_content))
            conn.commit()
        except mysql.connector.Error as err:
            # print(f"Error saving message: {err}") # Dihilangkan dari log
            pass
        finally:
            cursor.close()
            conn.close()

def get_chat_history(username1=None, username2=None, group_name=None):
    conn = get_db_connection()
    history = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        try:
            query = """
                SELECT 
                    u_sender.username as sender_username, 
                    m.message_content, 
                    m.timestamp,
                    u_receiver.username as receiver_username,
                    g.group_name
                FROM messages m
                JOIN users u_sender ON m.sender_id = u_sender.id
                LEFT JOIN users u_receiver ON m.receiver_id = u_receiver.id
                LEFT JOIN groups g ON m.group_id = g.id
                WHERE 1=1
            """
            params = []

            if username1 and username2: # Private chat history
                user_id1 = get_user_id(username1)
                user_id2 = get_user_id(username2)
                query += " AND ((m.sender_id = %s AND m.receiver_id = %s) OR (m.sender_id = %s AND m.receiver_id = %s))"
                params.extend([user_id1, user_id2, user_id2, user_id1])
            elif group_name: # Group chat history
                group_id = get_group_id(group_name)
                if group_id:
                    query += " AND m.group_id = %s"
                    params.append(group_id)
                else:
                    return "" # Group not found
            else: # Public chat history (messages without specific receiver or group)
                query += " AND m.receiver_id IS NULL AND m.group_id IS NULL"

            query += " ORDER BY m.timestamp ASC LIMIT 100"
            
            cursor.execute(query, tuple(params))
            for row in cursor.fetchall():
                timestamp_str = row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                if row['group_name']:
                    history.append(f"[{timestamp_str}] [GROUP {row['group_name']}] {row['sender_username']}: {row['message_content']}")
                elif row['receiver_username']:
                    history.append(f"[{timestamp_str}] [PRIVATE from {row['sender_username']} to {row['receiver_username']}] {row['message_content']}")
                else:
                    history.append(f"[{timestamp_str}] {row['sender_username']}: {row['message_content']}")
        except mysql.connector.Error as err:
            # print(f"Error getting chat history: {err}") # Dihilangkan dari log
            pass
        finally:
            cursor.close()
            conn.close()
    return "|||".join(history)

# --- Friendship Functions ---
def add_friend_request(sender_username, receiver_username):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            sender_id = get_user_id(sender_username)
            receiver_id = get_user_id(receiver_username)
            if not sender_id or not receiver_id:
                return "SERVER_ERROR: Pengguna tidak ditemukan."

            # Ensure user_id1 < user_id2 for consistency
            u1, u2 = sorted([sender_id, receiver_id])

            cursor.execute("SELECT status FROM friendships WHERE (user_id1 = %s AND user_id2 = %s)", (u1, u2))
            existing_friendship = cursor.fetchone()

            if existing_friendship:
                if existing_friendship[0] == 'accepted':
                    return "SERVER_INFO: Kalian sudah berteman."
                elif existing_friendship[0] == 'pending':
                    return "SERVER_INFO: Permintaan sudah terkirim atau sedang menunggu diterima."
                elif existing_friendship[0] == 'blocked':
                    return "SERVER_ERROR: Anda diblokir oleh pengguna ini atau telah memblokirnya."

            # If no existing relationship or it's new
            # If sender is u1 (smaller ID), it's a new pending request.
            # If sender is u2 (larger ID), it means u1 might have sent a request previously, or this is a new one.
            # We want 'pending' status for new requests.
            cursor.execute("INSERT INTO friendships (user_id1, user_id2, status) VALUES (%s, %s, 'pending')", (u1, u2))
            conn.commit()
            
            # Send notification to receiver
            if receiver_username in clients:
                receiver_socket = clients[receiver_username]
                send_encrypted_message(receiver_socket, f"MESSAGE:[SERVER] {sender_username} telah mengirim permintaan pertemanan kepada Anda.")
                send_encrypted_message(receiver_socket, "GET_PENDING_REQUESTS") # Update their pending list

            return "SERVER_INFO: Permintaan pertemanan berhasil dikirim."
        except mysql.connector.Error as err:
            # print(f"Error adding friend request: {err}") # Dihilangkan dari log
            return "SERVER_ERROR: Gagal mengirim permintaan pertemanan."
        finally:
            cursor.close()
            conn.close()

def respond_friend_request(responder_username, requester_username, status): # 'accepted' or 'rejected'
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            responder_id = get_user_id(responder_username)
            requester_id = get_user_id(requester_username)
            if not responder_id or not requester_id:
                return "SERVER_ERROR: Pengguna tidak ditemukan."

            u1, u2 = sorted([responder_id, requester_id])

            cursor.execute("UPDATE friendships SET status = %s WHERE (user_id1 = %s AND user_id2 = %s) AND status = 'pending'",
                           (status, u1, u2))
            conn.commit()

            if cursor.rowcount > 0:
                # Notify both users
                if status == 'accepted':
                    broadcast_message(f"[SERVER] {responder_username} menerima permintaan pertemanan dari {requester_username}.", include_sender=False)
                    send_encrypted_message(clients.get(requester_username), "GET_FRIEND_LIST")
                    send_encrypted_message(clients.get(responder_username), "GET_FRIEND_LIST")
                elif status == 'rejected':
                    broadcast_message(f"[SERVER] {responder_username} menolak permintaan pertemanan dari {requester_username}.", include_sender=False)
                
                # Update pending list for the responder
                send_encrypted_message(clients.get(responder_username), "GET_PENDING_REQUESTS")
                return f"SERVER_INFO: Permintaan pertemanan {status}."
            else:
                return "SERVER_ERROR: Permintaan pertemanan tidak ditemukan atau sudah diproses."
        except mysql.connector.Error as err:
            # print(f"Error responding to friend request: {err}") # Dihilangkan dari log
            return "SERVER_ERROR: Gagal memproses permintaan pertemanan."
        finally:
            cursor.close()
            conn.close()

def get_friend_list(username):
    conn = get_db_connection()
    friends = []
    if conn:
        cursor = conn.cursor()
        try:
            user_id = get_user_id(username)
            if not user_id: return ""

            cursor.execute("""
                SELECT u.username FROM users u
                JOIN friendships f ON (
                    (f.user_id1 = %s AND f.user_id2 = u.id) OR
                    (f.user_id2 = %s AND f.user_id1 = u.id)
                )
                WHERE f.status = 'accepted' AND u.id != %s
            """, (user_id, user_id, user_id))
            for row in cursor.fetchall():
                friends.append(row[0])
        except mysql.connector.Error as err:
            # print(f"Error getting friend list: {err}") # Dihilangkan dari log
            pass
        finally:
            cursor.close()
            conn.close()
    return ",".join(friends)

def get_pending_requests(username):
    conn = get_db_connection()
    pending_requests = []
    if conn:
        cursor = conn.cursor()
        try:
            user_id = get_user_id(username)
            if not user_id: return ""

            # Permintaan yang dikirim ke saya (saya adalah user_id2, status pending)
            cursor.execute("""
                SELECT u.username FROM users u
                JOIN friendships f ON f.user_id1 = u.id
                WHERE f.user_id2 = %s AND f.status = 'pending'
            """, (user_id,))
            for row in cursor.fetchall():
                pending_requests.append(row[0])
        except mysql.connector.Error as err:
            # print(f"Error getting pending requests: {err}") # Dihilangkan dari log
            pass
        finally:
            cursor.close()
            conn.close()
    return ",".join(pending_requests)

# --- Group Functions ---
def create_new_group(group_name, creator_username):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            creator_id = get_user_id(creator_username)
            if not creator_id:
                return "SERVER_ERROR: Pengguna pembuat grup tidak ditemukan."

            cursor.execute("SELECT id FROM groups WHERE group_name = %s", (group_name,))
            if cursor.fetchone():
                return "SERVER_ERROR: Nama grup sudah digunakan."

            cursor.execute("INSERT INTO groups (group_name, created_by) VALUES (%s, %s)", (group_name, creator_id))
            group_id = cursor.lastrowid
            
            # Add creator as a member
            cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (%s, %s)", (group_id, creator_id))
            conn.commit()

            broadcast_message(f"[SERVER] Grup '{group_name}' telah dibuat oleh {creator_username}.", include_sender=False)
            # Update group list for all online users
            for user in clients.keys():
                send_encrypted_message(clients.get(user), "GET_GROUP_LIST")

            return "SERVER_INFO: Grup berhasil dibuat."
        except mysql.connector.Error as err:
            # print(f"Error creating group: {err}") # Dihilangkan dari log
            return "SERVER_ERROR: Gagal membuat grup."
        finally:
            cursor.close()
            conn.close()

def join_existing_group(group_name, username):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            user_id = get_user_id(username)
            cursor.execute("SELECT id FROM groups WHERE group_name = %s", (group_name,))
            group_result = cursor.fetchone()
            if not group_result:
                return "SERVER_ERROR: Grup tidak ditemukan."
            group_id = group_result[0]

            cursor.execute("SELECT * FROM group_members WHERE group_id = %s AND user_id = %s", (group_id, user_id))
            if cursor.fetchone():
                return "SERVER_INFO: Anda sudah menjadi anggota grup ini."

            cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (%s, %s)", (group_id, user_id))
            conn.commit()

            broadcast_message(f"[SERVER] {username} telah bergabung ke grup '{group_name}'.", include_sender=False)
            # Update group list for the user who joined
            send_encrypted_message(clients.get(username), "GET_GROUP_LIST")
            return "SERVER_INFO: Berhasil bergabung ke grup."
        except mysql.connector.Error as err:
            # print(f"Error joining group: {err}") # Dihilangkan dari log
            return "SERVER_ERROR: Gagal bergabung ke grup."
        finally:
            cursor.close()
            conn.close()

def get_group_id(group_name):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM groups WHERE group_name = %s", (group_name,))
            result = cursor.fetchone()
            return result[0] if result else None
        except mysql.connector.Error as err:
            # print(f"Error getting group ID: {err}") # Dihilangkan dari log
            return None
        finally:
            cursor.close()
            conn.close()

def get_group_members(group_id):
    conn = get_db_connection()
    members = []
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT u.username FROM users u
                JOIN group_members gm ON u.id = gm.user_id
                WHERE gm.group_id = %s
            """, (group_id,))
            for row in cursor.fetchall():
                members.append(row[0])
        except mysql.connector.Error as err:
            # print(f"Error getting group members: {err}") # Dihilangkan dari log
            pass
        finally:
            cursor.close()
            conn.close()
    return members

def get_user_groups(username):
    conn = get_db_connection()
    groups = []
    if conn:
        cursor = conn.cursor()
        try:
            user_id = get_user_id(username)
            if not user_id: return ""

            cursor.execute("""
                SELECT g.group_name FROM groups g
                JOIN group_members gm ON g.id = gm.group_id
                WHERE gm.user_id = %s
            """, (user_id,))
            for row in cursor.fetchall():
                groups.append(row[0])
        except mysql.connector.Error as err:
            # print(f"Error getting user groups: {err}") # Dihilangkan dari log
            pass
        finally:
            cursor.close()
            conn.close()
    return ",".join(groups)

# --- Fungsi Broadcast Pesan ---
def send_encrypted_message(client_socket, message):
    try:
        encrypted_message = encrypt(message)
        client_socket.send(encrypted_message.encode('utf-8'))
    except Exception as e:
        print(f"[ERROR SEND_ENCRYPTED] Gagal mengirim pesan: {e}")

def broadcast_message(message, sender_socket=None, include_sender=True):
    for username, client_socket in list(clients.items()): 
        try:
            if client_socket != sender_socket or include_sender:
                send_encrypted_message(client_socket, f"MESSAGE:{message}")
        except Exception as e:
            print(f"[ERROR BROADCAST] Gagal mengirim ke {username}: {e}")
            remove_client(username)

def broadcast_user_list():
    user_list = ",".join(clients.keys())
    for username, client_socket in list(clients.items()):
        try:
            send_encrypted_message(client_socket, f"USER_LIST:{user_list}")
        except Exception as e:
            print(f"[ERROR BROADCAST USERLIST] Gagal mengirim ke {username}: {e}")
            remove_client(username)

def remove_client(username):
    if username in clients:
        del clients[username]
    if username in logged_in_users_id:
        del logged_in_users_id[username]
    print(f"[SERVER] {username} dihapus dari daftar klien aktif.")
    broadcast_message(f"[SERVER] {username} telah keluar.", include_sender=False)
    broadcast_user_list()

# --- Fungsi Penanganan Klien ---
def handle_client(client_socket, addr):
    global user_id_counter
    print(f"[KONEKSI BARU] {addr} terhubung.")
    logged_in_username = None
    user_id = None

    try:
        while True:
            encrypted_message = client_socket.recv(4096).decode('utf-8')
            if not encrypted_message:
                print(f"Klien {addr} terputus secara normal (recv kosong).")
                break 

            message = decrypt(encrypted_message)
            # print(f"[DITERIMA dari {addr}] {message}") # Dihilangkan dari log, hanya tampilkan jika benar-benar perlu debug

            if message.startswith("LOGIN:"):
                parts = message.split(':', 2)
                if len(parts) == 3:
                    username = parts[1]
                    password_hash = parts[2]
                    
                    if username in clients:
                        response = "ALREADY_LOGGED_IN"
                    else:
                        response = authenticate_user(username, password_hash)
                    
                    send_encrypted_message(client_socket, response)

                    if response == "LOGIN_SUCCESS":
                        logged_in_username = username
                        user_id_counter += 1
                        user_id = user_id_counter
                        clients[logged_in_username] = client_socket
                        logged_in_users_id[logged_in_username] = user_id
                        print(f"[SERVER] {logged_in_username} (ID: {user_id}) berhasil login.")
                        
                        send_encrypted_message(client_socket, f"ID_ASSIGNED:{user_id}")
                        
                        broadcast_message(f"[SERVER] {logged_in_username} telah bergabung.", include_sender=False)
                        broadcast_user_list()
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Invalid LOGIN format")

            elif message.startswith("REGISTER:"):
                parts = message.split(':', 2)
                if len(parts) == 3:
                    username = parts[1]
                    password_hash = parts[2]
                    response = register_user(username, password_hash)
                    send_encrypted_message(client_socket, response)
                    # print(f"[SERVER] Percobaan registrasi untuk {username}: {response}") # Dihilangkan jika tidak perlu debug registrasi
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Invalid REGISTER format")

            elif message.startswith("CHAT:"): # Public Chat
                if logged_in_username:
                    parts = message.split(':', 2)
                    if len(parts) == 3:
                        sender = parts[1]
                        content = parts[2]
                        full_message = f"[{datetime.now().strftime('%H:%M')}] {sender}: {content}"
                        save_message(sender, content) 
                        broadcast_message(full_message, client_socket, include_sender=True)
                    else:
                        send_encrypted_message(client_socket, "SERVER_ERROR: Invalid CHAT format")
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in to chat")
            
            elif message.startswith("PRIVATE_CHAT:"):
                if logged_in_username:
                    parts = message.split(':', 3) # Target:Sender:Message
                    if len(parts) == 4:
                        target_username = parts[1]
                        sender_username = parts[2]
                        content = parts[3]

                        if target_username == sender_username:
                            send_encrypted_message(client_socket, "SERVER_ERROR: Tidak bisa mengirim pesan pribadi ke diri sendiri.")
                            continue

                        # Check if target is a friend (optional but good practice)
                        # For simplicity, we allow private chat if target is logged in
                        if target_username in clients:
                            full_message = f"[{datetime.now().strftime('%H:%M')}] [PRIVATE] From {sender_username}: {content}"
                            send_encrypted_message(clients[target_username], f"MESSAGE:{full_message}")
                            # Also send to sender for their own chat history view
                            send_encrypted_message(client_socket, f"MESSAGE:[{datetime.now().strftime('%H:%M')}] [PRIVATE] To {target_username}: {content}")
                            save_message(sender_username, content, receiver_username=target_username)
                        else:
                            send_encrypted_message(client_socket, f"SERVER_ERROR: Pengguna '{target_username}' tidak ditemukan atau tidak online.")
                    else:
                        send_encrypted_message(client_socket, "SERVER_ERROR: Invalid PRIVATE_CHAT format")
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in to send private chat")

            elif message.startswith("GROUP_CHAT:"):
                if logged_in_username:
                    parts = message.split(':', 3) # GroupName:Sender:Message
                    if len(parts) == 4:
                        group_name = parts[1]
                        sender_username = parts[2]
                        content = parts[3]

                        group_id = get_group_id(group_name)
                        if not group_id:
                            send_encrypted_message(client_socket, "SERVER_ERROR: Grup tidak ditemukan.")
                            continue
                        
                        # Check if sender is a member of the group
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        sender_id = get_user_id(sender_username)
                        cursor.execute("SELECT * FROM group_members WHERE group_id = %s AND user_id = %s", (group_id, sender_id))
                        is_member = cursor.fetchone()
                        cursor.close()
                        conn.close()

                        if not is_member:
                            send_encrypted_message(client_socket, f"SERVER_ERROR: Anda bukan anggota grup '{group_name}'.")
                            continue

                        full_message = f"[{datetime.now().strftime('%H:%M')}] [GROUP {group_name}] {sender_username}: {content}"
                        save_message(sender_username, content, group_name=group_name)
                        
                        members_usernames = get_group_members(group_id)
                        for member_username in members_usernames:
                            if member_username in clients: # Only send to online members
                                send_encrypted_message(clients[member_username], f"MESSAGE:{full_message}")
                    else:
                        send_encrypted_message(client_socket, "SERVER_ERROR: Invalid GROUP_CHAT format")
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in to send group chat")

            elif message == "LOGOUT":
                if logged_in_username:
                    print(f"[SERVER] {logged_in_username} (ID: {user_id}) logout.")
                    send_encrypted_message(client_socket, "LOGOUT_SUCCESS")
                    remove_client(logged_in_username)
                    logged_in_username = None 
                    user_id = None
                    break
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in")
            
            elif message.startswith("DELETE_ACCOUNT:"):
                if logged_in_username:
                    parts = message.split(':', 2)
                    if len(parts) == 3:
                        username_to_delete = parts[1]
                        password_hash_confirm = parts[2]
                        if username_to_delete == logged_in_username: 
                            response = delete_user_from_db(username_to_delete, password_hash_confirm)
                            if response == "DELETE_SUCCESS":
                                print(f"[SERVER] Akun {logged_in_username} (ID: {user_id}) dihapus.")
                                send_encrypted_message(client_socket, "DELETE_SUCCESS")
                                remove_client(logged_in_username)
                                logged_in_username = None
                                user_id = None
                                break
                            elif response == "DELETE_FAILED_AUTH":
                                send_encrypted_message(client_socket, "SERVER_ERROR: Password salah.")
                            else:
                                send_encrypted_message(client_socket, "SERVER_ERROR: Gagal menghapus akun.")
                        else:
                             send_encrypted_message(client_socket, "SERVER_ERROR: Tidak berhak menghapus akun ini.")
                    else:
                        send_encrypted_message(client_socket, "SERVER_ERROR: Invalid DELETE_ACCOUNT format")
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in to delete account")

            elif message == "GET_USER_LIST":
                if logged_in_username:
                    user_list = ",".join(clients.keys())
                    send_encrypted_message(client_socket, f"USER_LIST:{user_list}")
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in to get user list")

            elif message == "GET_CHAT_HISTORY":
                if logged_in_username:
                    history = get_chat_history() # By default, gets public chat history
                    send_encrypted_message(client_socket, f"CHAT_HISTORY:{history}")
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in to get chat history")

            elif message.startswith("ADD_FRIEND:"):
                if logged_in_username:
                    target_user = message.split(':', 1)[1].strip()
                    response = add_friend_request(logged_in_username, target_user)
                    send_encrypted_message(client_socket, response)
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in.")
            
            elif message.startswith("ACCEPT_FRIEND:"):
                if logged_in_username:
                    requester_user = message.split(':', 1)[1].strip()
                    response = respond_friend_request(logged_in_username, requester_user, 'accepted')
                    send_encrypted_message(client_socket, response)
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in.")

            elif message.startswith("REJECT_FRIEND:"):
                if logged_in_username:
                    requester_user = message.split(':', 1)[1].strip()
                    response = respond_friend_request(logged_in_username, requester_user, 'rejected')
                    send_encrypted_message(client_socket, response)
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in.")

            elif message == "GET_FRIEND_LIST":
                if logged_in_username:
                    friend_list = get_friend_list(logged_in_username)
                    send_encrypted_message(client_socket, f"FRIEND_LIST:{friend_list}")
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in.")

            elif message == "GET_PENDING_REQUESTS":
                if logged_in_username:
                    pending_requests = get_pending_requests(logged_in_username)
                    send_encrypted_message(client_socket, f"PENDING_REQUESTS:{pending_requests}")
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in.")
            
            elif message.startswith("CREATE_GROUP:"):
                if logged_in_username:
                    group_name = message.split(':', 1)[1].strip()
                    response = create_new_group(group_name, logged_in_username)
                    send_encrypted_message(client_socket, response)
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in.")

            elif message.startswith("JOIN_GROUP:"):
                if logged_in_username:
                    group_name = message.split(':', 1)[1].strip()
                    response = join_existing_group(group_name, logged_in_username)
                    send_encrypted_message(client_socket, response)
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in.")

            elif message == "GET_GROUP_LIST":
                if logged_in_username:
                    group_list = get_user_groups(logged_in_username)
                    send_encrypted_message(client_socket, f"GROUP_LIST:{group_list}")
                else:
                    send_encrypted_message(client_socket, "SERVER_ERROR: Not logged in.")
            
            # --- Perubahan di sini: Mengatasi perintah yang digabung ---
            # Jika pesan yang diterima bukan format yang dikenal, periksa apakah itu gabungan dari perintah-perintah yang valid.
            elif logged_in_username and ("GET_USER_LIST" in message or "GET_FRIEND_LIST" in message or "GET_PENDING_REQUESTS" in message or "GET_GROUP_LIST" in message):
                # Jangan tampilkan pesan ini jika itu adalah kombinasi perintah yang valid
                pass 
            else:
                if logged_in_username:
                    # print(f"[SERVER] Pesan tidak dikenal dari {logged_in_username}: {message}") # Dihilangkan dari log
                    send_encrypted_message(client_socket, "SERVER_MESSAGE: Perintah tidak dikenal.")
                else:
                    # print(f"[SERVER] Pesan tidak dikenal dari {addr} (belum login): {message}") # Dihilangkan dari log
                    send_encrypted_message(client_socket, "SERVER_MESSAGE: Silakan login terlebih dahulu.")

    except ConnectionResetError:
        print(f"Klien {addr} terputus secara paksa.")
    except Exception as e:
        print(f"[ERROR HANDLE CLIENT {addr}] {e}")
    finally:
        if logged_in_username:
            remove_client(logged_in_username)
        try:
            client_socket.close()
        except Exception as e:
            print(f"[ERROR] Gagal menutup socket klien: {e}")

# --- Fungsi Utama Server ---
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Server mendengarkan di {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

if __name__ == "__main__":
    conn = get_db_connection()
    if conn:
        # print("Koneksi database berhasil!") # Dihilangkan dari log
        conn.close()
        create_users_table()
        create_friendships_table() 
        create_groups_table() 
        create_group_members_table() 
        create_messages_table() 
        start_server()
    else:
        print("Gagal terhubung ke database. Pastikan MySQL berjalan dan konfigurasi DB_CONFIG benar.")