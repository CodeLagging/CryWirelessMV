# banner.py
import sys
import platform
from debugs import debug

def check_os():
    if platform.system() == "Windows":
        debug("critical", "This tool is not supported on Windows")
        debug("critical", "Please use Linux (Kali, Ubuntu, Debian, etc.)")
        sys.exit(1)

def print_banner():
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗██████╗ ██╗   ██╗      ██╗    ██╗██╗███████╗██╗  ║
║  ██╔════╝██╔══██╗╚██╗ ██╔╝      ██║    ██║██║██╔════╝██║  ║
║  ██║     ██████╔╝ ╚████╔╝ █████╗██║ █╗ ██║██║█████╗  ██║  ║
║  ██║     ██╔══██╗  ╚██╔╝  ╚════╝██║███╗██║██║██╔══╝  ██║  ║
║  ╚██████╗██║  ██║   ██║         ╚███╔███╔╝██║██║     ██║  ║
║   ╚═════╝╚═╝  ╚═╝   ╚═╝          ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝  ║
║                                                           ║
║                      Version 2.0                          ║
║            WiFi & BLE Penetration Testing Tool            ║
║                 Created By - CodeLagging                  ║
╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def bluetooth():
    print("\n╔═════════════════════════════════════════════════════════════════════════╗")
    print("║                    CryWireless V2 - Bluetooth Scanner                   ║")
    print("╚═════════════════════════════════════════════════════════════════════════╝")

def scan_results():
    print("\n╔════════════════════════════════════════════════════════════════════════╗")
    print("║                             Scan Summary                               ║")
    print("╚════════════════════════════════════════════════════════════════════════╝")

def ble_menu():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║          CryWireless V2 - BLE Attack Module            ║")
    print("╚════════════════════════════════════════════════════════╝")

def wifi_attack():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║            CryWireless V2 - Attack Mode                ║")
    print("╚════════════════════════════════════════════════════════╝")

def other_attacks():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║              Other Attacks Available                   ║")
    print("╚════════════════════════════════════════════════════════╝")

if __name__ == "__main__":
    print_banner()
    bluetooth()
    scan_results()
    ble_menu()
    wifi_attack()
    other_attacks()
    check_os()