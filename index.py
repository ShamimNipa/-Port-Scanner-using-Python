
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address


def check_ip(target):
    """Validate an IP address or resolve a hostname."""
    target = target.strip()

    try:
        ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as exc:
            raise ValueError(f"Invalid target or hostname: {target}") from exc


def scan_port(ipaddress, port):
    """Check whether a TCP port is open."""
    try:
        with socket.create_connection(
            (ipaddress, port), timeout=1
        ) as sock:
            try:
                sock.settimeout(1)
                banner = sock.recv(1024).decode(
                    "utf-8", errors="replace"
                ).strip()

                if banner:
                    return f"[+] Port {port} is open: {banner}"

            except (socket.timeout, ConnectionError, OSError):
                pass

            return f"[+] Port {port} is open: No banner retrieved"

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan(target, start_port, end_port):
    """Scan a target using a limited number of worker threads."""
    try:
        converted_ip = check_ip(target)
    except ValueError as exc:
        print(f"[-] {exc}")
        return

    print(
        f"\n[#] Scanning target: {converted_ip} "
        f"from port {start_port} to {end_port}"
    )

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [
            executor.submit(scan_port, converted_ip, port)
            for port in range(start_port, end_port + 1)
        ]

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    print(result)
            except Exception as exc:
                print(f"[-] Scan error: {exc}")


def main():
    targets = input(
        "[+] Enter authorized target(s), separated by commas: "
    )

    port_range = input(
        "[+] Enter port range (e.g. 20-80): "
    ).strip()

    try:
        if "-" not in port_range:
            raise ValueError("Enter a range such as 20-80.")

        start_port, end_port = map(
            int, port_range.split("-")
        )

        if not (1 <= start_port <= end_port <= 65535):
            raise ValueError(
                "Ports must be between 1 and 65535, "
                "with the start port no greater than the end port."
            )

        target_list = [
            target.strip()
            for target in targets.split(",")
            if target.strip()
        ]

        if not target_list:
            raise ValueError("Please enter at least one target.")

    except ValueError as exc:
        print(f"[-] Invalid input: {exc}")
        return

    for target in target_list:
        scan(target, start_port, end_port)


if __name__ == "__main__":
    main()
