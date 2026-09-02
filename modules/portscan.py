import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time


MAX_WORKERS = 100
TIMEOUT = 0.5


def scan_port(ip, port):
    """
    Check whether a single TCP port is open.
    """

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(TIMEOUT)

        result = sock.connect_ex(
            (ip, port)
        )

        sock.close()

        if result == 0:
            return port

    except Exception:
        pass

    return None


def run_scan(target, results):
    """
    Perform a concurrent TCP port scan.
    """

    print("\n")
    print("=" * 55)
    print("                 TCP PORT SCANNER")
    print("=" * 55)

    # Resolve target
    try:
        ip = socket.gethostbyname(target)

    except socket.gaierror:

        print(
            f"\n[-] Could not resolve target: {target}"
        )

        results.add(
            "port_scan",
            {
                "target": target,
                "ip": None,
                "ports_scanned": 0,
                "open_ports": [],
                "scan_time": 0,
                "error": "DNS resolution failed"
            }
        )

        return

    print(f"\nTarget : {target}")
    print(f"IP     : {ip}")
    print("Ports  : 1-1000")

    print(
        f"\n[*] Using {MAX_WORKERS} concurrent workers..."
    )

    print("[*] Starting scan...\n")

    start_time = time()

    open_ports = []

    total_ports = 1000
    completed = 0

    # Concurrent scan
    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                scan_port,
                ip,
                port
            ): port
            for port in range(1, total_ports + 1)
        }

        for future in as_completed(futures):

            completed += 1

            try:
                port = future.result()

                if port is not None:

                    print(
                        f"[+] Port {port} OPEN"
                    )

                    open_ports.append(port)

            except Exception:
                pass

            # Display progress every 50 ports
            if (
                completed % 50 == 0
                or completed == total_ports
            ):

                print(
                    f"[*] Progress: "
                    f"{completed}/{total_ports} "
                    f"| Open: {len(open_ports)}"
                )

    open_ports.sort()

    elapsed = time() - start_time

    # Store results
    results.add(
        "port_scan",
        {
            "target": target,
            "ip": ip,
            "ports_scanned": total_ports,
            "open_ports": open_ports,
            "scan_time": round(
                elapsed,
                2
            )
        }
    )

    # Display final result
    print("\n" + "=" * 55)
    print("                 SCAN COMPLETE")
    print("=" * 55)

    print(
        f"\nScan time: {elapsed:.2f} seconds"
    )

    print(
        f"Ports scanned: {total_ports}"
    )

    print(
        f"Open ports: {len(open_ports)}"
    )

    if open_ports:

        print("\nOpen Ports:")

        for port in open_ports:

            print(
                f"  {port}/tcp"
            )

    else:

        print(
            "\n[-] No open ports found."
        )
