import socket

SERVER = '127.0.0.1'   # Zmień na swój adres honeypota

PORTS = {
    'telnet': 2323,
    'ssh': 2222,
    'http': 8080,
}

TESTS = {
    'telnet': [
        ("Podejrzany - root", b"root"),
        ("Podejrzany - admin", b"admin"),
        ("Podejrzany - 1234", b"1234"),
        ("Podejrzany - telnet shell", b"telnet shell"),
        ("Podejrzany - wget", b"wget busybox"),
        ("Podejrzany - hasło", b"password"),
        ("Normalny - user123", b"user123"),
        ("Normalny - hello world", b"hello world"),
    ],
    'ssh': [
        ("Podejrzany - root", b"Trying root login"),
        ("Podejrzany - admin", b"admin access"),
        ("Podejrzany - password", b"password attempt"),
        ("Podejrzany - ssh2", b"SSH2 client"),
        ("Podejrzany - OpenSSH_", b"OpenSSH_7.9"),
        ("Podejrzany - exploit", b"exploit code"),
        ("Podejrzany - masscan", b"masscan scanning"),
        ("Podejrzany - nmap", b"nmap scan"),
        ("Podejrzany - hydra", b"hydra brute force"),
        ("Za krótki", b"abc"),
        ("Normalny - zwykły banner", b"SSH-2.0-OpenSSH_8.2p1 Ubuntu"),
    ],
    'http': [
        ("Podejrzany - metoda DELETE", b"DELETE /admin HTTP/1.1 Host: localhost"),
        ("Podejrzany - SQL Injection OR", b"GET /index.php?id=1 OR 1=1 HTTP/1.1 Host: localhost"),
        ("Podejrzany - User-Agent sqlmap", b"GET / HTTP/1.1 Host: localhost\ User-Agent: sqlmap"),
        ("Podejrzany - bardzo krótkie", b"GET / H"),
        ("Normalny - GET", b"GET /index.html HTTP/1.1 Host: localhost"),
        ("Normalny - POST", b"POST /submit HTTP/1.1 Host: localhost Content-Length: 5 hello"),
    ],
}

def run_test(protocol, payload):
    port = PORTS[protocol]
    print(f"\n--- Test {protocol.upper()} ---")
    print(f"Wysyłam ({len(payload)} bajtów):")
    print(payload.decode(errors='ignore'))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(60)
        sock.connect((SERVER, port))
        sock.sendall(payload)

        response = sock.recv(4096)
        print("Odpowiedź serwera:")
        print(response.decode(errors='ignore'))

    except Exception as e:
        print(f"Błąd: {e}")
    finally:
        sock.close()

def multithread_test():
    import threading


    threads = []
    for protocol in TESTS:
        for desc, payload in TESTS[protocol]:
            print(f"[{protocol.upper()}] Test: {desc}")
            t = threading.Thread(target=run_test, args=(protocol, payload))
            threads.append(t)
            t.start()
            

    for thread in threads:
        thread.join()  # Czekamy na zakończenie wszystkich wątków

def legacy_test():
    for protocol in TESTS:
        for desc, payload in TESTS[protocol]:
            print(f"\n[{protocol.upper()}] Test: {desc}")
            run_test(protocol, payload)
def main():
    # Aby testować wersję Legacy (jednowątkową), odkomentuj poniższą linię:
    #legacy_test()

    # Aby testować wersję Multithread (wielowątkową), odkomentuj poniższą linię:
    multithread_test()

if __name__ == "__main__":
    main()
