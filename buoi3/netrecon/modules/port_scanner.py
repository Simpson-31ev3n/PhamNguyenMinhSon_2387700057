import asyncio, logging, socket
from datetime import datetime

logging.basicConfig(filename='netrecon.log', level=logging.INFO)

def log(message):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"[{now}] {message}")

async def scan_port(target, port, semaphore, open_ports=None):
    try:
        async with semaphore:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1)
            log(f"Port {port} is open on {target}")
            print(f"[+] {port}/tcp open")
            if open_ports is not None:
                open_ports.append(f"[+] {port}/tcp open")
            writer.close()
            await writer.wait_closed()
    except:
        pass

async def async_scan_ports(target, ports, rate_limit=100):
    semaphore = asyncio.Semaphore(rate_limit)
    open_ports = []
    tasks = [scan_port(target, port, semaphore, open_ports) for port in ports]
    await asyncio.gather(*tasks)
    return "\n".join(open_ports) if open_ports else "No open ports detected"
