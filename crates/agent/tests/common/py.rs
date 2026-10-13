//! Python endpoints for the netns tests (python3 is on every CI runner and host).

pub const ECHO: &str = r#"
import socket, sys, threading
def echo(c):
    while (d := c.recv(64)):
        c.sendall(d)
def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    while True:
        threading.Thread(target=echo, args=(s.accept()[0],), daemon=True).start()
for p in sys.argv[1:]:
    threading.Thread(target=serve, args=(int(p),), daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
"#;

/// Exit 0 when a TCP echo round trip to host:port works within a second.
pub const PROBE: &str = r#"
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1)
    s.sendall(b"x")
    sys.exit(0 if s.recv(1) == b"x" else 1)
except OSError:
    sys.exit(1)
"#;

/// One open connection; prints "ok" per echo every 100 ms for argv[3] seconds.
pub const STREAM: &str = r#"
import socket, sys, time
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1)
s.settimeout(0.3)
end = time.monotonic() + float(sys.argv[3])
while time.monotonic() < end:
    try:
        s.sendall(b"x")
        if s.recv(1):
            print("ok", flush=True)
    except OSError:
        pass
    time.sleep(0.1)
"#;

/// Sends one UDP datagram from a chosen source address.
pub const SPOOF: &str = r#"
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.sendto(b"x", (sys.argv[2], int(sys.argv[3])))
"#;
