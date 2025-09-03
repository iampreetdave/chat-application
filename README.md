# chat-application
A python based chat application fully implemented in one single python file.

chat_app.py
contains a chat application with very basic UI , i tried implementing everything , only thing i am not able to achive is accurate chat history 
Start server: it listens for TCP connections and uses a framed JSON protocol (4-byte length prefix).

Clients connect, register/login (stored in SQLite with salted PBKDF2 hashes).

Rooms are created implicitly by joining a room name. Clients can provide an optional room password; if used, message payloads stored in DB are encrypted with a symmetric key derived from that room password (Fernet).

Clients can fetch room history; if history items are encrypted, the client will try to decrypt using the room password entered locally.

How to run (quick)
Start server (on same machine or a server reachable by clients):
python chat_app.py server --host 0.0.0.0 --port 9009

Start a client (on same machine or remote):
python chat_app.py client --host SERVER_IP --port 9009

You can run many clients; login/register, join rooms, chat, send files
