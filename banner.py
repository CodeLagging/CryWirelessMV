# banner.py
import sys
import platform
import time
import math
from debugs import debug

def check_os():
    if platform.system() == "Windows":
        debug("critical", "This tool is not supported on Windows")
        debug("critical", "Please use Linux (Kali, Ubuntu, Debian, etc.)")
        sys.exit(1)

def print_banner():
    lines = [
        "╔═══════════════════════════════════════════════════════════╗",
        "║                                                           ║",
        "║   ██████╗██████╗ ██╗   ██╗      ██╗    ██╗██╗███████╗██╗  ║",
        "║  ██╔════╝██╔══██╗╚██╗ ██╔╝      ██║    ██║██║██╔════╝██║  ║",
        "║  ██║     ██████╔╝ ╚████╔╝ █████╗██║ █╗ ██║██║█████╗  ██║  ║",
        "║  ██║     ██╔══██╗  ╚██╔╝  ╚════╝██║███╗██║██║██╔══╝  ██║  ║",
        "║  ╚██████╗██║  ██║   ██║         ╚███╔███╔╝██║██║     ██║  ║",
        "║   ╚═════╝╚═╝  ╚═╝   ╚═╝          ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝  ║",
        "║                                                           ║",
        "║                      Version 8.2                          ║",
        "║            WiFi & BLE Penetration Testing Tool            ║",
        "║                 Created By - CodeLagging                  ║",
        "╚═══════════════════════════════════════════════════════════╝",
    ]
    w, h = max(len(l) for l in lines), len(lines)
    lines = [l.ljust(w) for l in lines]
    g = lambda c: f"\033[38;5;{c}m"
    B = "\033[1m"
    R = "\033[0m"
    draw = lambda frame: (sys.stdout.write(f"\033[{h}A" + "".join("\033[K"+l+"\n" for l in frame)), sys.stdout.flush())

    sys.stdout.write("\033[?25l" + "\n"*h)
    for col in range(1, w+1):
        draw([f"{g(250)}{l[:col-1]}{R}{B}\033[97m{l[col-1:col]}{R}" for l in lines])
        time.sleep(0.011)
    draw([f"{B}\033[97m{l}{R}" for l in lines])
    time.sleep(0.2)
    t, dur, step = 0.0, 7.0, 0.02
    while t < dur:
        b = (math.sin(t * math.pi) + 1) / 2       # 0..1 smooth pulse
        code = round(241 + b * (255 - 241))        # gray..white
        bold = B if b > 0.5 else ""
        draw([f"{bold}{g(code)}{l}{R}" for l in lines])
        time.sleep(step)
        t += step
    for c in range(255, 231, -3):
        draw([f"{g(c)}{l}{R}" for l in lines])
        time.sleep(0.07)
    sys.stdout.write(f"\033[{h}A" + "\033[K\n"*h + f"\033[{h}A\033[?25h")
    sys.stdout.flush()


def bluetooth():
    print("\n╔═════════════════════════════════════════════════════════════════════════╗")
    print("║                    CryWireless V8 - Bluetooth Scanner                   ║")
    print("╚═════════════════════════════════════════════════════════════════════════╝")

def scan_results():
    print("\n╔════════════════════════════════════════════════════════════════════════╗")
    print("║                             Scan Summary                               ║")
    print("╚════════════════════════════════════════════════════════════════════════╝")

def ble_menu():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║          CryWireless V8 - BLE Attack Module            ║")
    print("╚════════════════════════════════════════════════════════╝")

def wifi_attack():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║            CryWireless V8 - Attack Mode                ║")
    print("╚════════════════════════════════════════════════════════╝")

def other_attacks():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║              Other Attacks Available                   ║")
    print("╚════════════════════════════════════════════════════════╝")

if __name__ == "__main__":
    bluetooth()
    scan_results()
    ble_menu()
    wifi_attack()
    other_attacks()
    check_os()
    print_banner()
