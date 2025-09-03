#!/usr/bin/env python3
"""
chat_app.py

Single-file advanced chat application:
- Run as server: python chat_app.py server --host 0.0.0.0 --port 9009
- Run as client: python chat_app.py client --host 127.0.0.1 --port 9009

Dependencies:
    pip install cryptography
"""

import argparse
import base64
import json
import os
import queue
import sqlite3
import socket
import struct
import threading
import time
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
from datetime import datetime
from hashlib import pbkdf2_hmac
from pathlib import Path
from tkinter.scrolledtext import ScrolledText

# cryptography for symmetric encryption (Fernet)
try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception as e:
    print("Missing dependency 'cryptography'. Install with: pip install cryptography")
    raise

# -------------------------
# Utilities and constants
# -------------------------
DB_FILE = "chat_server.db"
BUFFER = 4096
ENC = "utf-8"

# Simple framed TCP JSON: 4-byte length prefix followed by JSON bytes
def send_msg(sock, obj):
    data = json.dumps(obj).encode(ENC)
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_msg(sock):
    # returns Python object or None on disconnect
    header = recvall(sock, 4)
    if not header:
        return None
    (n,) = struct.unpack("!I", header)
    data = recvall(sock, n)
    if not data:
        return None
    return json.loads(data.decode(ENC))

def recvall(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf

def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def derive_key_from_password(password: str) -> bytes:
    # Derive a 32-byte key for Fernet from a password using PBKDF2 (static salt for demo).
    # In production use a per-user random salt stored and TLS.
    salt = b"chat_app_demo_salt"  # demo only
    key = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000, dklen=32)
    return base64.urlsafe_b64encode(key)

# -------------------------
# Server
# -------------------------
class ChatServer:
    def __init__(self, host="0.0.0.0", port=9009):
        self.host = host
        self.port = port
        self.sock = None
        self.clients = {}  # client_sock -> {username, addr, thread, current_room}
        self.rooms = {}    # room_name -> set(client_socks)
        self.lock = threading.Lock()
        self.setup_db()
        print(f"[SERVER] Ready (db={DB_FILE})")

    def setup_db(self):
        first = not os.path.exists(DB_FILE)
        self.db = sqlite3.connect(DB_FILE, check_same_thread=False)
        cur = self.db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash BLOB,
                salt BLOB
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room TEXT,
                sender TEXT,
                timestamp TEXT,
                is_file INTEGER,
                filename TEXT,
                payload BLOB
            )
        """)
        self.db.commit()
        if first:
            print("[SERVER] DB created")

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(50)
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        try:
            while True:
                client_sock, addr = self.sock.accept()
                t = threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("[SERVER] Shutting down")
            self.sock.close()

    def handle_client(self, client_sock, addr):
        print(f"[SERVER] Incoming {addr}")
        user = {"sock": client_sock, "addr": addr, "username": None, "room": None}
        with self.lock:
            self.clients[client_sock] = user
        try:
            while True:
                msg = recv_msg(client_sock)
                if msg is None:
                    break
                self.process_message(client_sock, msg)
        except Exception as e:
            print(f"[SERVER] Client handler exception: {e}")
        finally:
            self.disconnect_client(client_sock)

    def process_message(self, sock, msg):
        typ = msg.get("type")
        if typ == "register":
            self.handle_register(sock, msg)
        elif typ == "login":
            self.handle_login(sock, msg)
        elif typ == "join":
            self.handle_join(sock, msg)
        elif typ == "leave":
            self.handle_leave(sock, msg)
        elif typ == "message":
            self.handle_chat_message(sock, msg)
        elif typ == "file":
            self.handle_file(sock, msg)
        elif typ == "list_rooms":
            self.send_rooms_list(sock)
        elif typ == "get_history":
            self.send_history(sock, msg)
        else:
            send_msg(sock, {"type":"error","message":"Unknown message type."})

    # -----------------------
    # Auth & user management
    # -----------------------
    def handle_register(self, sock, msg):
        username = msg.get("username")
        password = msg.get("password")
        if not username or not password:
            send_msg(sock, {"type":"register_result", "ok":False, "error":"username/password required"})
            return
        cur = self.db.cursor()
        cur.execute("SELECT username FROM users WHERE username=?", (username,))
        if cur.fetchone():
            send_msg(sock, {"type":"register_result", "ok":False, "error":"username exists"})
            return
        # Create salted hash
        salt = os.urandom(16)
        pwd_hash = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
        cur.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, pwd_hash, salt))
        self.db.commit()
        send_msg(sock, {"type":"register_result", "ok":True})
        print(f"[SERVER] Registered user: {username}")

    def handle_login(self, sock, msg):
        username = msg.get("username")
        password = msg.get("password")
        if not username or not password:
            send_msg(sock, {"type":"login_result", "ok":False, "error":"username/password required"})
            return
        cur = self.db.cursor()
        cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            send_msg(sock, {"type":"login_result", "ok":False, "error":"no such user"})
            return
        stored_hash, salt = row
        calc = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
        if calc != stored_hash:
            send_msg(sock, {"type":"login_result", "ok":False, "error":"invalid password"})
            return
        # success
        with self.lock:
            self.clients[sock]["username"] = username
        send_msg(sock, {"type":"login_result", "ok":True})
        print(f"[SERVER] {username} logged in from {self.clients[sock]['addr']}")

    # -----------------------
    # Rooms & messaging
    # -----------------------
    def handle_join(self, sock, msg):
        room = msg.get("room")
        room_password = msg.get("room_password")  # optional - stored only in memory for this session
        if not room:
            send_msg(sock, {"type":"join_result", "ok":False, "error":"room required"})
            return
        username = self.clients[sock]["username"]
        if not username:
            send_msg(sock, {"type":"join_result", "ok":False, "error":"login required"})
            return
        with self.lock:
            # remove from old room
            old = self.clients[sock].get("room")
            if old and sock in self.rooms.get(old, set()):
                self.rooms[old].remove(sock)
            # add to new
            self.rooms.setdefault(room, set()).add(sock)
            self.clients[sock]["room"] = room
            # attach room password to client's meta (not stored server-side persistently)
            self.clients[sock]["room_password"] = room_password
        send_msg(sock, {"type":"join_result", "ok":True, "room":room})
        self.broadcast_system(room, f"{username} joined the room")
        print(f"[SERVER] {username} joined {room}")

    def handle_leave(self, sock, msg):
        room = msg.get("room")
        username = self.clients[sock]["username"]
        with self.lock:
            if room and room in self.rooms and sock in self.rooms[room]:
                self.rooms[room].remove(sock)
                self.clients[sock]["room"] = None
        send_msg(sock, {"type":"leave_result", "ok":True})
        self.broadcast_system(room, f"{username} left the room")

    def handle_chat_message(self, sock, msg):
        text = msg.get("text", "")
        room = msg.get("room")
        username = self.clients[sock]["username"]
        timestamp = now_str()
        is_file = 0
        filename = None
        payload = text.encode("utf-8")
        # If room has a password on client's session, encrypt payload before storing
        rp = self.clients[sock].get("room_password")
        if rp:
            f = Fernet(derive_key_from_password(rp))
            payload = f.encrypt(payload)
            enc_flag = True
        else:
            enc_flag = False
        # store to DB
        cur = self.db.cursor()
        cur.execute("INSERT INTO messages (room, sender, timestamp, is_file, filename, payload) VALUES (?,?,?,?,?,?)",
                    (room, username, timestamp, is_file, filename, payload))
        self.db.commit()
        # broadcast to room clients (we will send payload decrypted if receiver has room_password, else raw text)
        self.broadcast_room(room, {
            "type":"message",
            "room":room,
            "sender":username,
            "timestamp":timestamp,
            "text": text,
            "encrypted": enc_flag
        }, raw_payload=payload)

    def handle_file(self, sock, msg):
        # file transfer: client sends chunks as base64, server stores and broadcasts metadata
        room = msg.get("room")
        filename = msg.get("filename")
        b64 = msg.get("b64")  # full file base64 in this demo (ok for small files)
        username = self.clients[sock]["username"]
        timestamp = now_str()
        payload = base64.b64decode(b64.encode("ascii"))
        rp = self.clients[sock].get("room_password")
        if rp:
            f = Fernet(derive_key_from_password(rp))
            stored = f.encrypt(payload)
            enc_flag = True
        else:
            stored = payload
            enc_flag = False
        cur = self.db.cursor()
        cur.execute("INSERT INTO messages (room, sender, timestamp, is_file, filename, payload) VALUES (?,?,?,?,?,?)",
                    (room, username, timestamp, 1, filename, stored))
        self.db.commit()
        # broadcast file event, payload NOT sent (client should request history to download or clients can stream file).
        self.broadcast_room(room, {
            "type":"file_announcement",
            "room":room,
            "sender":username,
            "timestamp":timestamp,
            "filename":filename,
            "encrypted": enc_flag
        })

    def send_rooms_list(self, sock):
        with self.lock:
            rooms = list(self.rooms.keys())
        send_msg(sock, {"type":"rooms_list", "rooms":rooms})

    def send_history(self, sock, msg):
        room = msg.get("room")
        limit = int(msg.get("limit", 100))
        # fetch last N messages
        cur = self.db.cursor()
        cur.execute("SELECT sender, timestamp, is_file, filename, payload FROM messages WHERE room=? ORDER BY id DESC LIMIT ?", (room, limit))
        rows = cur.fetchall()
        # return newest-first reversed
        rows.reverse()
        out = []
        for sender, timestamp, is_file, filename, payload in rows:
            if is_file:
                out.append({"sender":sender, "timestamp":timestamp, "is_file":1, "filename":filename})
            else:
                # deliver payload as text if possible; but server can't decrypt if encrypted and room password unknown.
                # We send payload as base64 if it's not UTF-8
                try:
                    text = payload.decode("utf-8")
                    out.append({"sender":sender, "timestamp":timestamp, "is_file":0, "text":text, "encrypted":False})
                except Exception:
                    out.append({"sender":sender, "timestamp":timestamp, "is_file":0, "payload_b64":base64.b64encode(payload).decode("ascii"), "encrypted":True})
        send_msg(sock, {"type":"history", "room":room, "messages":out})

    # -----------------------
    # Broadcast helpers
    # -----------------------
    def broadcast_room(self, room, obj, raw_payload=None):
        # obj is JSON to send; for files we may omit payloads.
        with self.lock:
            targets = list(self.rooms.get(room, set()))
        for s in targets:
            try:
                # If receiver has room_password and the message was encrypted, server can't decrypt, but can send payload_b64 for client to decrypt locally if requested.
                send_msg(s, obj)
            except Exception as e:
                print(f"[SERVER] Broadcast failed to {s}: {e}")

    def broadcast_system(self, room, text):
        obj = {"type":"system", "room":room, "text":text, "timestamp":now_str()}
        self.broadcast_room(room, obj)

    def disconnect_client(self, sock):
        with self.lock:
            meta = self.clients.pop(sock, None)
            if meta:
                username = meta.get("username")
                room = meta.get("room")
                if room and sock in self.rooms.get(room, set()):
                    self.rooms[room].remove(sock)
                    self.broadcast_system(room, f"{username} disconnected")
        try:
            sock.close()
        except:
            pass

# -------------------------
# Client (Tkinter GUI)
# -------------------------
class ChatClientApp:
    def __init__(self, server_host="127.0.0.1", server_port=9009):
        self.server_host = server_host
        self.server_port = server_port
        self.sock = None
        self.username = None
        self.room = None
        self.room_password = None  # optional symmetric room password (for client-side encryption/decryption)
        self.receive_thread = None
        self.recv_queue = queue.Queue()
        self.root = tk.Tk()
        self.root.title("ChatApp")
        self.build_login_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def connect(self):
        if self.sock:
            return True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.server_host, self.server_port))
            self.sock = s
            # start receiver
            self.receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
            self.receive_thread.start()
            return True
        except Exception as e:
            messagebox.showerror("Connection error", f"Could not connect: {e}")
            return False

    def receive_loop(self):
        while True:
            try:
                msg = recv_msg(self.sock)
                if msg is None:
                    self.recv_queue.put({"type":"system", "text":"Disconnected from server"})
                    break
                self.recv_queue.put(msg)
            except Exception as e:
                self.recv_queue.put({"type":"system", "text":f"Receive error: {e}"})
                break

    # ----------------------
    # UI: Login / Register
    # ----------------------
    def build_login_ui(self):
        for w in self.root.winfo_children():
            w.destroy()
        frm = tk.Frame(self.root, padx=10, pady=10)
        frm.pack(fill="both", expand=True)
        tk.Label(frm, text="Server Host:").grid(row=0, column=0, sticky="e")
        self.e_host = tk.Entry(frm); self.e_host.insert(0, self.server_host)
        self.e_host.grid(row=0, column=1)
        tk.Label(frm, text="Server Port:").grid(row=1, column=0, sticky="e")
        self.e_port = tk.Entry(frm); self.e_port.insert(0, str(self.server_port))
        self.e_port.grid(row=1, column=1)
        tk.Label(frm, text="Username:").grid(row=2, column=0, sticky="e")
        self.e_user = tk.Entry(frm); self.e_user.grid(row=2, column=1)
        tk.Label(frm, text="Password:").grid(row=3, column=0, sticky="e")
        self.e_pass = tk.Entry(frm, show="*"); self.e_pass.grid(row=3, column=1)
        btn_login = tk.Button(frm, text="Login", command=self.ui_do_login)
        btn_reg = tk.Button(frm, text="Register", command=self.ui_do_register)
        btn_login.grid(row=4, column=0, pady=8)
        btn_reg.grid(row=4, column=1, pady=8)
        self.status = tk.Label(frm, text="Not connected", fg="blue")
        self.status.grid(row=5, column=0, columnspan=2)
        self.root.after(200, self.poll_recv_queue)

    def ui_do_register(self):
        host = self.e_host.get().strip(); port = int(self.e_port.get().strip())
        self.server_host = host; self.server_port = port
        if not self.connect():
            return
        username = self.e_user.get().strip(); password = self.e_pass.get().strip()
        send_msg(self.sock, {"type":"register", "username":username, "password":password})
        # wait for response in queue
        self.root.after(200, self._wait_login_result)

    def ui_do_login(self):
        host = self.e_host.get().strip(); port = int(self.e_port.get().strip())
        self.server_host = host; self.server_port = port
        if not self.connect():
            return
        username = self.e_user.get().strip(); password = self.e_pass.get().strip()
        send_msg(self.sock, {"type":"login", "username":username, "password":password})
        self.root.after(200, self._wait_login_result)

    def _wait_login_result(self):
        # check queue for login/register results synchronously (small wait)
        processed = False
        try:
            while True:
                msg = self.recv_queue.get_nowait()
                typ = msg.get("type")
                if typ == "login_result":
                    if msg.get("ok"):
                        self.username = self.e_user.get().strip()
                        self.build_main_ui()
                    else:
                        messagebox.showerror("Login failed", msg.get("error",""))
                elif typ == "register_result":
                    if msg.get("ok"):
                        messagebox.showinfo("Registered", "Registration successful. Now log in.")
                    else:
                        messagebox.showerror("Register failed", msg.get("error",""))
                else:
                    # stash
                    self.recv_queue.put(msg)
                    break
                processed = True
        except queue.Empty:
            pass
        if not processed:
            # not ready yet, check again soon
            self.root.after(200, self._wait_login_result)

    # ----------------------
    # UI: Main Chat Window
    # ----------------------
    def build_main_ui(self):
        for w in self.root.winfo_children():
            w.destroy()
        self.root.title(f"ChatApp - {self.username}")
        top = tk.Frame(self.root)
        top.pack(side="top", fill="x")
        tk.Label(top, text=f"Logged in as: {self.username}").pack(side="left")
        btn_refresh_rooms = tk.Button(top, text="Refresh Rooms", command=self.request_rooms)
        btn_refresh_rooms.pack(side="right")
        # left: rooms
        left = tk.Frame(self.root)
        left.pack(side="left", fill="y", padx=5, pady=5)
        tk.Label(left, text="Rooms").pack()
        self.lst_rooms = tk.Listbox(left, width=20, height=20)
        self.lst_rooms.pack()
        self.lst_rooms.bind("<Double-Button-1>", self.on_room_double)
        tk.Button(left, text="Join Room", command=self.ui_join_room).pack(fill="x")
        tk.Button(left, text="Create Room (enter name below)", command=self.ui_join_room).pack(fill="x")
        self.e_new_room = tk.Entry(left); self.e_new_room.pack(fill="x")
        tk.Label(left, text="Room Password (optional for encryption)").pack()
        self.e_room_pass = tk.Entry(left, show="*"); self.e_room_pass.pack(fill="x")
        # right: chat
        right = tk.Frame(self.root)
        right.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        self.lbl_room = tk.Label(right, text="No room", font=("Arial", 14))
        self.lbl_room.pack(anchor="w")
        self.txt_area = ScrolledText(right, state="disabled", height=20)
        self.txt_area.pack(fill="both", expand=True)
        bottom = tk.Frame(right)
        bottom.pack(fill="x")
        self.e_msg = tk.Entry(bottom)
        self.e_msg.pack(side="left", fill="x", expand=True)
        self.e_msg.bind("<Return>", lambda e: self.ui_send_message())
        tk.Button(bottom, text="Send", command=self.ui_send_message).pack(side="left")
        tk.Button(bottom, text="Send File", command=self.ui_send_file).pack(side="left")
        tk.Button(bottom, text="Get History", command=self.ui_get_history).pack(side="left")
        # statusbar
        self.status = tk.Label(self.root, text="Connected", bd=1, relief="sunken", anchor="w")
        self.status.pack(side="bottom", fill="x")
        # initial rooms fetch
        self.request_rooms()
        self.root.after(200, self.poll_recv_queue)

    def request_rooms(self):
        send_msg(self.sock, {"type":"list_rooms"})

    def ui_join_room(self):
        sel = self.lst_rooms.curselection()
        if sel:
            room = self.lst_rooms.get(sel[0])
        else:
            room = self.e_new_room.get().strip()
        if not room:
            messagebox.showwarning("Room", "Enter or select a room name")
            return
        rp = self.e_room_pass.get().strip() or None
        self.room_password = rp
        send_msg(self.sock, {"type":"join", "room":room, "room_password":rp})

    def on_room_double(self, event):
        self.ui_join_room()

    def ui_send_message(self):
        text = self.e_msg.get().strip()
        if not text or not self.room:
            return
        send_msg(self.sock, {"type":"message", "room":self.room, "text":text})
        self.e_msg.delete(0, "end")

    def ui_send_file(self):
        if not self.room:
            messagebox.showwarning("Room", "Join a room first")
            return
        path = filedialog.askopenfilename()
        if not path:
            return
        # read file small size demo
        with open(path, "rb") as f:
            data = f.read()
        b64 = base64.b64encode(data).decode("ascii")
        filename = Path(path).name
        send_msg(self.sock, {"type":"file", "room":self.room, "filename":filename, "b64":b64})
        messagebox.showinfo("File sent", f"File {filename} announced to room")

    def ui_get_history(self):
        if not self.room:
            return
        send_msg(self.sock, {"type":"get_history", "room":self.room, "limit":200})

    # ----------------------
    # Incoming message handling
    # ----------------------
    def poll_recv_queue(self):
        try:
            while True:
                msg = self.recv_queue.get_nowait()
                self.handle_incoming(msg)
        except queue.Empty:
            pass
        self.root.after(150, self.poll_recv_queue)

    def handle_incoming(self, msg):
        typ = msg.get("type")
        if typ == "rooms_list":
            self.lst_rooms.delete(0, "end")
            for r in msg.get("rooms", []):
                self.lst_rooms.insert("end", r)
        elif typ == "join_result":
            if msg.get("ok"):
                self.room = msg.get("room")
                self.lbl_room.config(text=f"Room: {self.room}")
                self.txt_area.config(state="normal"); self.txt_area.delete("1.0","end"); self.txt_area.config(state="disabled")
                self.status.config(text=f"In room {self.room}")
                # fetch history automatically
                self.ui_get_history()
            else:
                messagebox.showerror("Join failed", msg.get("error",""))
        elif typ == "message":
            room = msg.get("room")
            if room != self.room:
                return
            sender = msg.get("sender"); text = msg.get("text"); ts = msg.get("timestamp"); encrypted = msg.get("encrypted", False)
            if encrypted:
                # server stored encrypted; it might have sent payload_b64 in history only. For live messages, server sends text unencrypted.
                self.append_text(f"[{ts}] {sender}: (encrypted message) {text}\n")
            else:
                self.append_text(f"[{ts}] {sender}: {text}\n")
            self.notify_window()
        elif typ == "system":
            room = msg.get("room")
            if room and room != self.room:
                return
            text = msg.get("text"); ts = msg.get("timestamp", now_str())
            self.append_text(f"[{ts}] *SYSTEM*: {text}\n")
            self.notify_window()
        elif typ == "file_announcement":
            room = msg.get("room")
            if room != self.room:
                return
            sender = msg.get("sender"); filename = msg.get("filename"); ts = msg.get("timestamp")
            self.append_text(f"[{ts}] {sender} sent a file: {filename} (use Get History to download if available)\n")
            self.notify_window()
        elif typ == "history":
            room = msg.get("room")
            if room != self.room:
                return
            for m in msg.get("messages", []):
                ts = m.get("timestamp"); sender = m.get("sender")
                if m.get("is_file"):
                    fn = m.get("filename")
                    self.append_text(f"[{ts}] {sender} sent file: {fn}\n")
                else:
                    if m.get("encrypted"):
                        # payload_b64 present
                        b64 = m.get("payload_b64")
                        # try to decrypt with room password if we have it
                        if self.room_password:
                            try:
                                f = Fernet(derive_key_from_password(self.room_password))
                                raw = f.decrypt(base64.b64decode(b64))
                                text = raw.decode("utf-8")
                                self.append_text(f"[{ts}] {sender}: {text}\n")
                            except InvalidToken:
                                self.append_text(f"[{ts}] {sender}: (encrypted, wrong room password)\n")
                        else:
                            self.append_text(f"[{ts}] {sender}: (encrypted, provide room password to decrypt)\n")
                    else:
                        text = m.get("text")
                        self.append_text(f"[{ts}] {sender}: {text}\n")
        elif typ == "login_result":
            # forwarded to wait function but if arriving here, handle gracefully
            if not msg.get("ok"):
                messagebox.showerror("Login Failed", msg.get("error",""))
        else:
            # generic messages
            self.append_text(f"[{now_str()}] {json.dumps(msg)}\n")

    def append_text(self, s):
        self.txt_area.config(state="normal")
        self.txt_area.insert("end", s)
        self.txt_area.see("end")
        self.txt_area.config(state="disabled")

    def notify_window(self):
        try:
            self.root.bell()
        except:
            pass

    def on_close(self):
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# -------------------------
# CLI and entrypoint
# -------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["server", "client"], help="Run mode")
    parser.add_argument("--host", default="127.0.0.1", help="Host for server/client")
    parser.add_argument("--port", default=9009, type=int, help="Port for server/client")
    args = parser.parse_args()
    if args.mode == "server":
        s = ChatServer(host=args.host, port=args.port)
        s.start()
    else:
        app = ChatClientApp(server_host=args.host, server_port=args.port)
        app.connect()
        app.run()

if __name__ == "__main__":
    main()
