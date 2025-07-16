import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import tkinter.ttk as ttk
import datetime
import hashlib
from PIL import Image, ImageTk, ImageDraw # Import ImageDraw for potential overlay


# --- Konfigurasi Server ---
SERVER_HOST = '192.168.56.1'  # Pastikan ini sesuai dengan IP server Anda
SERVER_PORT = 12345

# --- Kunci Substitution Cipher (HARUS SAMA dengan di server!) ---
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
        encrypted_text += ENCRYPTION_KEY.get(char, char) # Gunakan .get() untuk menangani karakter yang tidak ada di key
    return encrypted_text

def decrypt(text):
    decrypted_text = ""
    for char in text:
        decrypted_text += DECRYPTION_KEY.get(char, char) # Gunakan .get() untuk menangani karakter yang tidak ada di key
    return decrypted_text

# --- Variabel Global ---
client_socket = None
root = None
chat_box = None
message_entry = None
username_display = None
user_list_box = None
friends_list_box = None # Untuk daftar teman
pending_requests_list_box = None # Untuk permintaan pertemanan
groups_list_box = None # Untuk daftar grup
logged_in_username = None # Pastikan ini diinisialisasi
user_id = None
chat_screen_frame = None
current_chat_target = None # Untuk melacak siapa atau grup mana yang sedang di-chat

# --- Fungsi Koneksi Jaringan ---
def connect_to_server():
    global client_socket
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        return True
    except ConnectionRefusedError:
        messagebox.showerror("Koneksi Gagal", "Tidak dapat terhubung ke server. Pastikan server berjalan.")
        return False
    except Exception as e:
        messagebox.showerror("Error Koneksi", f"Terjadi kesalahan saat mencoba koneksi: {e}")
        return False

def send_message_to_server(message):
    try:
        encrypted_message = encrypt(message)
        client_socket.send(encrypted_message.encode('utf-8'))
    except Exception as e:
        print(f"[ERROR SEND] {e}")
        messagebox.showerror("Kirim Gagal", "Koneksi ke server terputus atau gagal mengirim pesan.")
        if root:
            root.quit()

def receive_messages():
    global chat_box, logged_in_username
    while True:
        try:
            encrypted_data = client_socket.recv(4096).decode('utf-8')
            if not encrypted_data:
                break
            data = decrypt(encrypted_data)

            print(f"[DEBUG CLIENT RECEIVE] {data}")

            # Pisahkan perintah dari pesan
            if data.startswith("MESSAGE:"):
                message = data[len("MESSAGE:"):].strip()
                chat_box.config(state=tk.NORMAL)
                # Cek apakah pesan adalah notifikasi dari server atau pesan chat
                if message.startswith("[SERVER]") or "telah bergabung" in message or "telah keluar" in message or "mengirim permintaan pertemanan" in message or "menerima permintaan pertemanan" in message or "menolak permintaan pertemanan" in message or "membuat grup" in message or "bergabung ke grup" in message:
                    chat_box.insert(tk.END, f"{message}\n", "server_message")
                elif message.startswith("[PRIVATE]"):
                    chat_box.insert(tk.END, f"{message}\n", "private_message")
                elif message.startswith("[GROUP]"):
                    chat_box.insert(tk.END, f"{message}\n", "group_message")
                else:
                    chat_box.insert(tk.END, f"{message}\n")
                chat_box.config(state=tk.DISABLED)
                chat_box.see(tk.END)
            elif data.startswith("USER_LIST:"):
                user_list_str = data[len("USER_LIST:"):].strip()
                update_user_list(user_list_str)
            elif data.startswith("FRIEND_LIST:"):
                friend_list_str = data[len("FRIEND_LIST:"):].strip()
                update_friends_list(friend_list_str)
            elif data.startswith("PENDING_REQUESTS:"):
                pending_requests_str = data[len("PENDING_REQUESTS:"):].strip()
                update_pending_requests_list(pending_requests_str)
            elif data.startswith("GROUP_LIST:"):
                group_list_str = data[len("GROUP_LIST:"):].strip()
                update_groups_list(group_list_str)
            elif data.startswith("ID_ASSIGNED:"):
                global user_id
                user_id = data[len("ID_ASSIGNED:"):].strip()
                print(f"ID yang Diterima: {user_id}")
            elif data.startswith("CHAT_HISTORY:"):
                history = data[len("CHAT_HISTORY:"):].strip()
                display_chat_history(history)
            elif data == "LOGOUT_SUCCESS":
                messagebox.showinfo("Logout", "Anda telah berhasil logout.")
                for widget in root.winfo_children():
                    widget.destroy()
                show_login_screen()
                break
            elif data == "DELETE_SUCCESS":
                messagebox.showinfo("Hapus Akun", "Akun Anda telah berhasil dihapus.")
                for widget in root.winfo_children():
                    widget.destroy()
                show_login_screen()
                break
            elif data.startswith("SERVER_INFO:"):
                info_message = data[len("SERVER_INFO:"):].strip()
                messagebox.showinfo("Info Server", info_message)
            elif data.startswith("SERVER_ERROR:"):
                error_message = data[len("SERVER_ERROR:"):].strip()
                messagebox.showerror("Error Server", error_message)
            else:
                chat_box.config(state=tk.NORMAL)
                chat_box.insert(tk.END, f"[RAW DATA]: {data}\n")
                chat_box.config(state=tk.DISABLED)
                chat_box.see(tk.END)

        except ConnectionResetError:
            messagebox.showerror("Koneksi Terputus", "Koneksi ke server telah terputus.")
            if root:
                root.quit()
            break
        except OSError as e:
            if "Bad file descriptor" in str(e):
                print("[INFO] Socket ditutup, menghentikan thread penerima.")
                break
            else:
                print(f"[ERROR RECEIVE] {e}")
                break
        except Exception as e:
            print(f"[ERROR RECEIVE] {e}")
            break

def display_chat_history(history_data):
    global chat_box
    chat_box.config(state=tk.NORMAL)
    chat_box.delete(1.0, tk.END)

    if history_data:
        messages = history_data.split('|||')
        for msg in messages:
            if msg:
                parts = msg.split(':::')
                if len(parts) == 3:
                    timestamp_str, sender, content = parts
                    chat_box.insert(tk.END, f"[{timestamp_str}] {sender}: {content}\n")
    chat_box.config(state=tk.DISABLED)
    chat_box.see(tk.END)

def update_user_list(user_list_str):
    global user_list_box
    user_list_box.delete(0, tk.END)
    users = user_list_str.split(',')
    for user in users:
        if user.strip() and user.strip() != logged_in_username:
            user_list_box.insert(tk.END, user.strip())

def update_friends_list(friend_list_str):
    global friends_list_box
    friends_list_box.delete(0, tk.END)
    friends = friend_list_str.split(',')
    for friend in friends:
        if friend.strip():
            friends_list_box.insert(tk.END, friend.strip())

def update_pending_requests_list(pending_requests_str):
    global pending_requests_list_box
    pending_requests_list_box.delete(0, tk.END)
    requests = pending_requests_str.split(',')
    for req in requests:
        if req.strip():
            pending_requests_list_box.insert(tk.END, req.strip())

def update_groups_list(group_list_str):
    global groups_list_box
    groups_list_box.delete(0, tk.END)
    groups = group_list_str.split(',')
    for group in groups:
        if group.strip():
            groups_list_box.insert(tk.END, group.strip())

# --- Fungsi Hashing Password ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- Fungsi GUI ---
def send_chat_message():
    global message_entry, logged_in_username, current_chat_target
    message = message_entry.get()
    if message.strip() and logged_in_username:
        if current_chat_target:
            # Jika target adalah grup (dimulai dengan #)
            if current_chat_target.startswith("#"):
                group_name = current_chat_target[1:]
                send_message_to_server(f"GROUP_CHAT:{group_name}:{logged_in_username}:{message}")
            # Jika target adalah pengguna pribadi
            else:
                send_message_to_server(f"PRIVATE_CHAT:{current_chat_target}:{logged_in_username}:{message}")
        else:
            # Jika tidak ada target spesifik, kirim sebagai chat publik
            send_message_to_server(f"CHAT:{logged_in_username}:{message}")
        message_entry.delete(0, tk.END)

def select_chat_target(event):
    global current_chat_target
    widget = event.widget
    selection = widget.curselection()
    if selection:
        selected_item = widget.get(selection[0])
        current_chat_target = selected_item
        messagebox.showinfo("Chat Target", f"Anda sekarang chatting dengan: {current_chat_target}")
    else:
        current_chat_target = None
        messagebox.showinfo("Chat Target", "Anda sekarang chatting di saluran publik.")


def send_friend_request():
    global user_list_box
    selection = user_list_box.curselection()
    if selection:
        selected_user = user_list_box.get(selection[0])
        if selected_user:
            send_message_to_server(f"ADD_FRIEND:{selected_user}")
            messagebox.showinfo("Permintaan Pertemanan", f"Permintaan pertemanan dikirim ke {selected_user}.")
    else:
        messagebox.showwarning("Peringatan", "Pilih pengguna dari daftar untuk mengirim permintaan pertemanan.")

def accept_friend_request():
    global pending_requests_list_box
    selection = pending_requests_list_box.curselection()
    if selection:
        selected_user = pending_requests_list_box.get(selection[0])
        if selected_user:
            send_message_to_server(f"ACCEPT_FRIEND:{selected_user}")
            messagebox.showinfo("Terima Pertemanan", f"Anda menerima permintaan pertemanan dari {selected_user}.")
    else:
        messagebox.showwarning("Peringatan", "Pilih permintaan dari daftar untuk diterima.")

def reject_friend_request():
    global pending_requests_list_box
    selection = pending_requests_list_box.curselection()
    if selection:
        selected_user = pending_requests_list_box.get(selection[0])
        if selected_user:
            send_message_to_server(f"REJECT_FRIEND:{selected_user}")
            messagebox.showinfo("Tolak Pertemanan", f"Anda menolak permintaan pertemanan dari {selected_user}.")
    else:
        messagebox.showwarning("Peringatan", "Pilih permintaan dari daftar untuk ditolak.")

def create_group():
    group_name = simpledialog.askstring("Buat Grup", "Masukkan nama grup baru:")
    if group_name and group_name.strip():
        send_message_to_server(f"CREATE_GROUP:{group_name.strip()}")

def join_group():
    group_name = simpledialog.askstring("Bergabung Grup", "Masukkan nama grup yang ingin Anda bergabung:")
    if group_name and group_name.strip():
        send_message_to_server(f"JOIN_GROUP:{group_name.strip()}")

def show_chat_screen():
    global root, chat_box, message_entry, username_display, user_list_box, friends_list_box, pending_requests_list_box, groups_list_box, chat_screen_frame, logged_in_username

    for widget in root.winfo_children():
        widget.destroy()

    chat_screen_frame = ttk.Frame(root, padding="10", style="Main.TFrame")
    chat_screen_frame.pack(fill=tk.BOTH, expand=True)

    # Header Frame (Username and Logout)
    header_frame = ttk.Frame(chat_screen_frame, style="Header.TFrame")
    header_frame.pack(fill=tk.X, pady=(0, 10))

    username_display = ttk.Label(header_frame, text=f"Selamat datang, {logged_in_username}!", font=("Arial", 14, "bold"), foreground="#333333")
    username_display.pack(side=tk.LEFT, padx=10, pady=5)

    logout_button = ttk.Button(header_frame, text="Logout", command=confirm_logout, style="Danger.TButton")
    logout_button.pack(side=tk.RIGHT, padx=10, pady=5)

    delete_account_button = ttk.Button(header_frame, text="Hapus Akun", command=confirm_delete_account, style="Outline.TButton")
    delete_account_button.pack(side=tk.RIGHT, padx=5, pady=5)

    # Main Content Area (User/Friend/Group List and Chat Box)
    content_frame = ttk.Frame(chat_screen_frame, style="ChatArea.TFrame")
    content_frame.pack(fill=tk.BOTH, expand=True)

    # Left Panel: Navigation (Tabs for Users, Friends, Pending, Groups)
    left_panel_frame = ttk.Frame(content_frame, width=200, style="UserList.TFrame")
    left_panel_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
    left_panel_frame.pack_propagate(False)

    notebook = ttk.Notebook(left_panel_frame)
    notebook.pack(fill=tk.BOTH, expand=True, pady=(5,0))

    # Tab: Semua Pengguna
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    all_users_tab = ttk.Frame(notebook)
    notebook.add(all_users_tab, text="Semua Pengguna")

    ttk.Label(all_users_tab, text="Daftar Pengguna:", font=("Arial", 11, "bold"), background="#F5F5F5").pack(pady=5)
    user_list_box = tk.Listbox(all_users_tab, height=15, font=("Arial", 10), background="#F0F0F0", foreground="#333333", selectmode=tk.SINGLE)
    user_list_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    user_list_box.bind("<<ListboxSelect>>", select_chat_target)

    send_friend_request_button = ttk.Button(all_users_tab, text="Kirim Permintaan Pertemanan", command=send_friend_request, style="Accent.TButton")
    send_friend_request_button.pack(pady=5)

    # Tab: Teman
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)


    friends_tab = ttk.Frame(notebook)
    notebook.add(friends_tab, text="Teman")

    ttk.Label(friends_tab, text="Daftar Teman:", font=("Arial", 11, "bold"), background="#F5F5F5").pack(pady=5)
    friends_list_box = tk.Listbox(friends_tab, height=15, font=("Arial", 10), background="#F0F0F0", foreground="#333333", selectmode=tk.SINGLE)
    friends_list_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    friends_list_box.bind("<<ListboxSelect>>", select_chat_target)

    # Tab: Permintaan Tertunda
    pending_tab = ttk.Frame(notebook)
    notebook.add(pending_tab, text="Permintaan Tertunda")

    ttk.Label(pending_tab, text="Permintaan Masuk:", font=("Arial", 11, "bold"), background="#F5F5F5").pack(pady=5)
    pending_requests_list_box = tk.Listbox(pending_tab, height=15, font=("Arial", 10), background="#F0F0F0", foreground="#333333", selectmode=tk.SINGLE)
    pending_requests_list_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    pending_button_frame = ttk.Frame(pending_tab)
    pending_button_frame.pack(pady=5)
    ttk.Button(pending_button_frame, text="Terima", command=accept_friend_request, style="Primary.TButton").pack(side=tk.LEFT, padx=2)
    ttk.Button(pending_button_frame, text="Tolak", command=reject_friend_request, style="Danger.TButton").pack(side=tk.RIGHT, padx=2)

    # Tab: Grup Saya
    groups_tab = ttk.Frame(notebook)
    notebook.add(groups_tab, text="Grup Saya")

    ttk.Label(groups_tab, text="Daftar Grup:", font=("Arial", 11, "bold"), background="#F5F5F5").pack(pady=5)
    groups_list_box = tk.Listbox(groups_tab, height=15, font=("Arial", 10), background="#F0F0F0", foreground="#333333", selectmode=tk.SINGLE)
    groups_list_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    groups_list_box.bind("<<ListboxSelect>>", lambda event: select_chat_target_group(event))

    group_button_frame = ttk.Frame(groups_tab)
    group_button_frame.pack(pady=5)
    ttk.Button(group_button_frame, text="Buat Grup", command=create_group, style="Accent.TButton").pack(side=tk.LEFT, padx=2)
    ttk.Button(group_button_frame, text="Gabung Grup", command=join_group, style="Outline.TButton").pack(side=tk.RIGHT, padx=2)

    # Right Panel: Chat Box (MODIFIED TO INCLUDE LOGO)
    chat_panel_frame = ttk.Frame(content_frame, style="ChatArea.TFrame")
    chat_panel_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    ttk.Label(chat_panel_frame, text="Obrolan:", font=("Arial", 11, "bold"), background="#F0F2F5").pack(anchor="w", pady=(0,5))

    # Create a Canvas for the background image
    chat_canvas = tk.Canvas(chat_panel_frame, bg="white", highlightthickness=0)
    chat_canvas.pack(fill=tk.BOTH, expand=True, padx=(5, 5), pady=(0, 5))

    # Load and display logo on the canvas
    logo_path = r"C:\Users\ASUS\Documents\kuliah\PBL SEM2\chat gui v2\ChatAja.png" # Changed to PNG
    # You also have a ChatAja.jpg, consider if you want to use that instead.
    # logo_path = r"C:\Users\ASUS\Documents\kuliah\PBL SEM2\chat gui v2\ChatAja.jpg"
    chat_canvas._logo_image = None

    try:
        print(f"Mencoba memuat logo dari: {logo_path}")
        original_image = Image.open(logo_path)
        print("Logo berhasil dimuat!")

        def resize_logo(event=None):
            if chat_canvas.winfo_width() == 1 or chat_canvas.winfo_height() == 1:
                return # Avoid division by zero on initial small size

            canvas_width = chat_canvas.winfo_width()
            canvas_height = chat_canvas.winfo_height()

            img_width, img_height = original_image.size

            # Calculate a ratio that fits the logo within the canvas while maintaining aspect ratio,
            # but also making it somewhat smaller so it doesn't dominate the background.
            # Let's target a max height of 60% of canvas height, or max width of 60% of canvas width.
            target_max_height = int(canvas_height * 0.6)
            target_max_width = int(canvas_width * 0.6)

            # Ensure the image doesn't go above a certain pixel size to avoid being too large
            MAX_PIXEL_SIZE = 300
            
            ratio_w = min(target_max_width / img_width, MAX_PIXEL_SIZE / img_width)
            ratio_h = min(target_max_height / img_height, MAX_PIXEL_SIZE / img_height)
            ratio = min(ratio_w, ratio_h)

            new_width = int(img_width * ratio)
            new_height = int(img_height * ratio)

            if new_width == 0 or new_height == 0: # Avoid errors with tiny sizes
                return

            resized_image = original_image.resize((new_width, new_height), Image.Resampling.LANCZOS)

            # Optional: Add a semi-transparent overlay to the logo to make text more readable
            # This makes the logo less "bright" but still visible.
            overlay = Image.new('RGBA', resized_image.size, (255, 255, 255, 100)) # White, 100 alpha (out of 255)
            # You can change the color (e.g., (0,0,0,100) for black overlay)
            # You can change the alpha (e.g., 50 for very subtle, 150 for more opaque)
            
            # Composite the logo with the overlay
            # If your logo is already somewhat transparent (like a PNG), you might want to adjust
            # how you composite it. For a solid JPG/PNG, a simple alpha_composite works well.
            if resized_image.mode != 'RGBA':
                resized_image = resized_image.convert('RGBA')
            
            final_image = Image.alpha_composite(resized_image, overlay)
            
            logo_image_tk = ImageTk.PhotoImage(final_image)

            chat_canvas._logo_image = logo_image_tk # Keep a reference!
            if hasattr(chat_canvas, '_image_id'):
                chat_canvas.delete(chat_canvas._image_id) # Delete old image before creating new one

            image_id = chat_canvas.create_image(
                canvas_width / 2,
                canvas_height / 2,
                image=logo_image_tk,
                anchor="center"
            )
            chat_canvas._image_id = image_id
            chat_canvas.tag_lower(image_id) # Ensure logo is behind chat_box

        chat_canvas.bind("<Configure>", resize_logo) # Resize logo on canvas resize
        
    except FileNotFoundError:
        print(f"ERROR: File logo tidak ditemukan di path: {logo_path}")
        chat_canvas.create_text(chat_canvas.winfo_width() / 2, chat_canvas.winfo_height() / 2,
                                text="Logo tidak ditemukan!", fill="red", font=('Arial', 12, 'bold'))
    except Exception as e:
        print(f"ERROR: Gagal memuat logo: {e}")
        chat_canvas.create_text(chat_canvas.winfo_width() / 2, chat_canvas.winfo_height() / 2,
                                text=f"Error memuat logo: {e}", fill="red", font=('Arial', 12, 'bold'))

    # Place the chat_box (scrolledtext) ON TOP OF THE CANVAS
    # Set background for chat_box to be explicitly the same as canvas or a slightly transparent color
    # Note: scrolledtext itself does not support true alpha transparency on its content area.
    # The 'bg' option sets its opaque background color. If you want true transparency,
    # you'd need a more complex solution (e.g., custom widget or layering with PIL).
    chat_box = scrolledtext.ScrolledText(chat_canvas, wrap=tk.WORD, state=tk.DISABLED, font=("Arial", 10),
                                         background="#FFFFFF", foreground="#333333", relief="flat", borderwidth=0, bd=0, # Changed borderwidth and bd to 0
                                         insertbackground="black" # Cursor color
                                        )
    # Create a window on the canvas to hold the scrolledtext widget
    chat_box_window = chat_canvas.create_window(0, 0, anchor="nw", window=chat_box, width=chat_canvas.winfo_width(), height=chat_canvas.winfo_height())
    chat_canvas._chat_box_window = chat_box_window # Store reference

    # Update chat_box window size when canvas resizes
    def on_canvas_resize_for_chatbox(event):
        chat_canvas.itemconfigure(chat_canvas._chat_box_window, width=event.width, height=event.height)
    chat_canvas.bind("<Configure>", on_canvas_resize_for_chatbox, add="+") # Add to existing bind

    # Configure tags for different message types
    chat_box.tag_config("server_message", foreground="#0000FF", font=("Arial", 10, "italic"))
    chat_box.tag_config("private_message", foreground="#8B008B", font=("Arial", 10, "bold"))
    chat_box.tag_config("group_message", foreground="#008000", font=("Arial", 10, "bold"))

    # Message Input Area
    input_frame = ttk.Frame(chat_panel_frame, style="Input.TFrame")
    input_frame.pack(fill=tk.X, pady=(5, 0))

    message_entry = ttk.Entry(input_frame, font=("Arial", 11), width=50)
    message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
    message_entry.bind("<Return>", lambda event: send_chat_message())

    send_button = ttk.Button(input_frame, text="Kirim", command=send_chat_message, style="Accent.TButton")
    send_button.pack(side=tk.RIGHT)

    # Request data when chat screen is shown
    send_message_to_server("GET_CHAT_HISTORY")
    send_message_to_server("GET_USER_LIST")
    send_message_to_server("GET_FRIEND_LIST")
    send_message_to_server("GET_PENDING_REQUESTS")
    send_message_to_server("GET_GROUP_LIST")

def select_chat_target_group(event):
    global current_chat_target
    widget = event.widget
    selection = widget.curselection()
    if selection:
        selected_item = widget.get(selection[0])
        current_chat_target = "#" + selected_item # Tambahkan '#' di depan untuk menandakan grup
        messagebox.showinfo("Chat Target", f"Anda sekarang chatting di grup: {selected_item}")
    else:
        current_chat_target = None
        messagebox.showinfo("Chat Target", "Anda sekarang chatting di saluran publik.")

def show_login_screen():
    global root, client_socket, logged_in_username

    if client_socket:
        try:
            client_socket.close()
        except Exception as e:
            print(f"Error closing socket: {e}")
        client_socket = None

    for widget in root.winfo_children():
        widget.destroy()

    if not connect_to_server():
        root.after(100, root.quit)
        return

    login_frame = ttk.Frame(root, padding="30 30 30 30", style="Card.TFrame")
    login_frame.pack(expand=True)

    ttk.Label(login_frame, text="Login ke Aplikasi Chat", font=("Arial", 16, "bold"), foreground="#333333").pack(pady=20)

    username_label = ttk.Label(login_frame, text="Username:", font=("Arial", 12))
    username_label.pack(anchor="w", pady=(10, 0))
    username_entry = ttk.Entry(login_frame, width=30, font=("Arial", 12))
    username_entry.pack(pady=(0, 10))

    password_label = ttk.Label(login_frame, text="Password:", font=("Arial", 12))
    password_label.pack(anchor="w", pady=(10, 0))
    password_entry = ttk.Entry(login_frame, show='*', width=30, font=("Arial", 12))
    password_entry.pack(pady=(0, 20))

    def attempt_login():
        nonlocal username_entry, password_entry
        global logged_in_username
        username = username_entry.get()
        password = password_entry.get()
        if not username or not password:
            messagebox.showwarning("Input Kosong", "Username dan password tidak boleh kosong.")
            return

        hashed_password = hash_password(password)
        send_message_to_server(f"LOGIN:{username}:{hashed_password}")

        response = decrypt(client_socket.recv(4096).decode('utf-8'))
        if response == "LOGIN_SUCCESS":
            logged_in_username = username
            messagebox.showinfo("Login Berhasil", f"Selamat datang, {username}!")
            threading.Thread(target=receive_messages, daemon=True).start()
            show_chat_screen()
        elif response == "LOGIN_FAILED":
            messagebox.showerror("Login Gagal", "Username atau password salah.")
        elif response == "ALREADY_LOGGED_IN":
            messagebox.showwarning("Login Gagal", "Pengguna ini sudah login.")
        else:
            messagebox.showerror("Error", f"Respon tidak dikenal: {response}")

    login_button = ttk.Button(login_frame, text="Login", command=attempt_login, style="Primary.TButton")
    login_button.pack(pady=(0, 10))

    ttk.Label(login_frame, text="Belum punya akun?", font=("Arial", 10)).pack(pady=(10, 0))
    register_button = ttk.Button(login_frame, text="Daftar Sekarang", command=show_register_screen, style="Link.TButton")
    register_button.pack()

    username_entry.focus_set()

def show_register_screen():
    global root

    for widget in root.winfo_children():
        widget.destroy()

    register_frame = ttk.Frame(root, padding="30 30 30 30", style="Card.TFrame")
    register_frame.pack(expand=True)

    ttk.Label(register_frame, text="Daftar Akun Baru", font=("Arial", 16, "bold"), foreground="#333333").pack(pady=20)

    username_label = ttk.Label(register_frame, text="Username:", font=("Arial", 12))
    username_label.pack(anchor="w", pady=(10, 0))
    username_entry = ttk.Entry(register_frame, width=30, font=("Arial", 12))
    username_entry.pack(pady=(0, 10))

    password_label = ttk.Label(register_frame, text="Password:", font=("Arial", 12))
    password_label.pack(anchor="w", pady=(10, 0))
    password_entry = ttk.Entry(register_frame, show='*', width=30, font=("Arial", 12))
    password_entry.pack(pady=(0, 10))

    confirm_password_label = ttk.Label(register_frame, text="Konfirmasi Password:", font=("Arial", 12))
    confirm_password_label.pack(anchor="w", pady=(10, 0))
    confirm_password_entry = ttk.Entry(register_frame, show='*', width=30, font=("Arial", 12))
    confirm_password_entry.pack(pady=(0, 20))

    def attempt_register():
        username = username_entry.get()
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()

        if not username or not password or not confirm_password:
            messagebox.showwarning("Input Kosong", "Semua kolom harus diisi.")
            return

        if password != confirm_password:
            messagebox.showwarning("Password Tidak Cocok", "Password dan konfirmasi password tidak cocok.")
            return

        hashed_password = hash_password(password)
        send_message_to_server(f"REGISTER:{username}:{hashed_password}")

        response = decrypt(client_socket.recv(4096).decode('utf-8'))
        if response == "REGISTER_SUCCESS":
            messagebox.showinfo("Pendaftaran Berhasil", "Akun berhasil dibuat! Silakan login.")
            show_login_screen()
        elif response == "USERNAME_TAKEN":
            messagebox.showerror("Pendaftaran Gagal", "Username sudah digunakan. Pilih username lain.")
        else:
            messagebox.showerror("Error", f"Respon tidak dikenal: {response}")

    register_button = ttk.Button(register_frame, text="Daftar", command=attempt_register, style="Primary.TButton")
    register_button.pack(pady=(0, 10))

    back_button = ttk.Button(register_frame, text="Kembali ke Login", command=show_login_screen, style="Link.TButton")
    back_button.pack()

    username_entry.focus_set()

def confirm_logout():
    if messagebox.askyesno("Konfirmasi Logout", "Apakah Anda yakin ingin logout?"):
        send_message_to_server("LOGOUT")

def confirm_delete_account():
    if messagebox.askyesno("Konfirmasi Hapus Akun", "Apakah Anda yakin ingin menghapus akun ini secara permanen? Tindakan ini tidak dapat dibatalkan."):
        password = simpledialog.askstring("Konfirmasi Password", "Masukkan password Anda untuk mengkonfirmasi penghapusan akun:", show='*')
        if password:
            hashed_password = hash_password(password)
            send_message_to_server(f"DELETE_ACCOUNT:{logged_in_username}:{hashed_password}")
        else:
            messagebox.showwarning("Batal", "Penghapusan akun dibatalkan.")

# --- Fungsi setup_gui utama ---
def setup_gui():
    global root
    root = tk.Tk()
    root.title("Chat aja")
    root.geometry("800x600")
    root.resizable(True, True)

    style = ttk.Style()
    style.theme_use('clam')

    primary_color = "#4CAF50"
    accent_color = "#2196F3"
    danger_color = "#DC3545"
    text_color = "#333333"
    background_color = "#910F8A"
    card_background = "white"

    style.configure('Main.TFrame', background=background_color)
    style.configure('Card.TFrame', background=card_background, relief="flat", borderwidth=1, bordercolor="#DDDDDD")
    style.configure('Header.TFrame', background="#E0E0E0")
    style.configure('ChatArea.TFrame', background=background_color)
    style.configure('UserList.TFrame', background="#F5F5F5")
    style.configure('Input.TFrame', background=background_color)

    style.configure('TLabel', background=card_background, foreground=text_color, font=('Arial', 11))
    style.configure('Header.TLabel', background="#E0E0E0", foreground=text_color)

    style.configure('TEntry', fieldbackground="white", bordercolor="#CCCCCC", relief="solid", borderwidth=1, foreground=text_color)
    style.map('TEntry', fieldbackground=[('focus', '#E8F0FE')])

    style.configure('TButton', font=('Arial', 10, 'bold'), borderwidth=0, relief="flat", padding=8)
    style.configure('Primary.TButton', background=primary_color, foreground='white')
    style.map('Primary.TButton', background=[('active', '#4CAF50')])
    style.configure('Accent.TButton', background=accent_color, foreground='white')
    style.map('Accent.TButton', background=[('active', '#1e84d4')])
    style.configure('Outline.TButton', background='white', foreground=accent_color, borderwidth=1, relief="solid", bordercolor=accent_color)
    style.map('Outline.TButton', foreground=[('active', 'white')], background=[('active', accent_color)])
    style.configure('Danger.TButton', background=danger_color, foreground='white')
    style.map('Danger.TButton', background=[('active', '#c82333')])
    style.configure('Link.TButton', background='white', foreground='#007BFF', font=('Arial', 10, 'underline'), relief='flat')
    style.map('Link.TButton', foreground=[('active', '#0056b3')], background=[('active', 'white')])

    style.configure('TNotebook.Tab', font=('Arial', 10, 'bold'), padding=[10, 5])
    style.map('TNotebook.Tab', background=[('selected', background_color)], foreground=[('selected', primary_color)])
    style.map('TNotebook.Tab', background=[('!selected', '#700D7D')], foreground=[('!selected', '#D0D0D0')])

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    main_frame = ttk.Frame(root, style='Main.TFrame')
    main_frame.grid(row=0, column=0, sticky="nsew")

    main_frame.grid_rowconfigure(1, weight=1)
    main_frame.grid_columnconfigure(0, weight=1)
    main_frame.grid_columnconfigure(1, weight=3)

    header_frame = ttk.Frame(main_frame, style='Header.TFrame')
    header_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
    header_frame.grid_columnconfigure(0, weight=1)

    welcome_label = ttk.Label(header_frame, text="Selamat datang, Pengguna!", style='Header.TLabel')
    welcome_label.grid(row=0, column=0, sticky="w")
    delete_account_button = ttk.Button(header_frame, text="Hapus Akun", style='Danger.TButton')
    delete_account_button.grid(row=0, column=1, padx=5)
    logout_button = ttk.Button(header_frame, text="Logout", style='Danger.TButton')
    logout_button.grid(row=0, column=2, padx=5)

    # These notebook and tabs related setups within setup_gui are mostly for initial display/structure,
    # but the actual active chat screen is managed by show_chat_screen().
    # You can remove this section from setup_gui if you always transition to show_chat_screen after login.
    # If setup_gui is only for initial styling and then show_login_screen is called,
    # then the elements within the notebook here will not be the ones used.
    # The crucial part is that show_chat_screen will build the whole layout again.

    # --- Panggil Login Screen ---
    show_login_screen()

    # --- Fungsi Penanganan Penutupan Jendela ---
    def on_closing():
        if client_socket:
            try:
                send_message_to_server("LOGOUT")
                import time
                time.sleep(0.5)
            except Exception as e:
                print(f"Error sending logout on close: {e}")
            finally:
                client_socket.close()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

# --- Main execution block ---
if __name__ == "__main__":
    setup_gui()