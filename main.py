# main.py
import os
import sys

from core.set_path import paths

path = os.getcwd()
paths(root_dir=path) # just incase lmao

from time import sleep as wait

from colorama import Fore, Style, init

init()

def startup():
    global debug, banner, ModuleSetup, HandshakeCaptureModule, BleModule, bluetooth, Scanner, ScannerAP
    try:
        import banner
        from core.log_config import configure_logging
        configure_logging()
        from debugs import debug
        debug("info", "Core Modules Loaded")
    # Cool fallback cuz theres always one broken installation on someone's system
    except ImportError as critical:
        print(f"{Fore.RED}[CRITICAL]: Core Module {critical.name}.py is missing{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[WARN]: See Error: {critical}")
        sys.exit(1)
    
    missing = [] # i wonder why its missing :D
    try: 
        from core.wifi_module import ModuleSetup
        globals()['ModuleSetup'] = ModuleSetup
    except ImportError: 
        ModuleSetup = None
        missing.append("wifi") # Why would wifi be missing, thats the whole point of this

    try:
        from core.BT_HCI.ble_module import BleModule
        globals()['BleModule'] = BleModule
    except ImportError:
        BleModule = None
        missing.append("ble")
    try:
        from core.BT_HCI.bluetooth import bluetooth
        globals()['bluetooth'] = bluetooth
    except ImportError:
        bluetooth = None
        missing.append("bluetooth") # bluetooth is optional, but its nice to have
    try: 
        from core.WIFI import HandshakeCaptureModule
        globals()['HandshakeCaptureModule'] = HandshakeCaptureModule
    except ImportError: 
        HandshakeCaptureModule = None
        missing.append("handshake") # youll love this, dont leave it
    
    try:
        from core.WIFI.scanner import Scanner
        globals()['Scanner'] = Scanner
    except ImportError:
        Scanner = None
        missing.append("scanner") # scanner is optional, but its nice to have
    
    try:
        from core.APCC.scanner_ap import ScannerAP
        globals()['ScannerAP'] = ScannerAP
    except ImportError:
        ScannerAP = None
        missing.append("scanner_ap") # ooh this is cool
    
    missing_set = set(missing)
    required_modules = {"wifi", "handshake", "ble"}
    if required_modules.issubset(missing_set):
        debug("critical", "No attack modules available. Exiting.")
        sys.exit(1)
    if missing:
        debug("warn", "Core Modules Limited:")
        for i in missing:
            debug("warn", f"Core Module '{i}' unavailable.")
    else: debug("ok", "All modules loaded")

    should_exit = main()
    return should_exit


# the fuck is this, why not shove cli_mode in here?
# cuz i have no fucking idea why.. im just lazy fr
def main():
    try:
        banner.check_os() # no there is no fucking windows or wsl support
        wait(2)
        os.system("clear")
        banner.print_banner()
        if os.geteuid() != 0:
            debug("critical", "Not running as sudo, could not start")
            sys.exit(1)
        
        
        # Main menu loop
        while True:
            try:
                if cli_mode():
                    break
            except KeyboardInterrupt:
                debug("warn", "Interrupted by user")
                break
            except Exception as e:  # noqa: BLE001
                debug("critical", f"Fatal error: {e}")
                break
    # ofcourse you need these, or maybe not
    # i dont care, youll have it anyway
    except KeyboardInterrupt:
        debug("warn", "Interrupted by user")
        sys.exit()
    except Exception as e:  # noqa: BLE001
        debug("critical", f"Fatal error: {e}")
        return False


# Just cuz its named cli_mode doesnt mean ill add a "gui_mode" later.
# i tried before, its a nightmare. never touhing that again.
def cli_mode():
    try:
        print("\nSelect Module:")
        if 'ModuleSetup' in globals() and ModuleSetup:
            print("1. WiFi Attack Module")
        else: print(f"{Fore.RED}1. WiFi Attack Module{Style.RESET_ALL}")
        if 'HandshakeCaptureModule' in globals() and HandshakeCaptureModule:
            print("2. Handshake Capture Module")
        else: print(f"{Fore.RED}2. Handshake Capture Module{Style.RESET_ALL}")
        if 'Scanner' in globals() and Scanner:
            print("3. PacketScanner Module")
        else: print(f"{Fore.RED}3. Packet Scanner Module{Style.RESET_ALL}")
        if 'ScannerAP' in globals() and ScannerAP:
            print("4. APCC Module")
        else: print(f"{Fore.RED}4. APCC Control Module{Style.RESET_ALL}")
        if 'BleModule' in globals() and BleModule:
            print("5. Ble Spam Module")
        if 'bluetooth' in globals() and bluetooth:
            print("6. Bluetooth Scanner Module")
        else: print(f"{Fore.RED}6. Bluetooth Scanner Module{Style.RESET_ALL}")
        print("0. Exit")
        
        choice = input("\nModule: ").strip()
        
        if choice == "1" or choice.lower() == "wifi":
            if 'ModuleSetup' not in globals() or not ModuleSetup:
                debug("critical", "WiFi module not loaded")
                return False
            wifi = ModuleSetup()
            wifi.run()
            return False

        elif choice == "2" or choice.lower() == "handshake":
            if 'HandshakeCaptureModule' not in globals() or not HandshakeCaptureModule:
                debug("critical", "Handshake Capture module not loaded")
                return False
            hc = HandshakeCaptureModule()
            hc.run()
            return False
        
        # ooh this is new
        elif choice == "3" or choice.lower() == "scanner":
            if 'Scanner' not in globals() or not Scanner:
                debug("critical", "Scanner module not loaded")
                return False
            interface = input("Interface to use (wlanX): ")
            scan = Scanner(iface=interface, savepath="./SCAN_scanner")
            scan.run()
            return False
        
        elif choice == "4" or choice.lower() == "APCC Module" or choice.lower() == "apcc":
            if 'ScannerAP' not in globals() or not ScannerAP:
                debug("critical", "AP Inspector module not loaded")
                return False
            interface = input("Interface to use (wlanX): ")
            scan = ScannerAP(iface=interface, savepath="./SCAN_inspector")
            scan.run()
            return False
        
        elif choice == "6" or choice.lower() == "ble advertisement":
            if 'BleModule' not in globals() or not BleModule:
                debug("critical", "Ble Module not loaded")
                return False
            try:
                hci = input("HCI Device: (e.g. 0, 1. 2, default 0)")
                if not hci:
                    hci = 0
                try:
                    int(hci)
                except ValueError:
                    debug("warn", "Invalid HCI device, defaulting to 0")
                    hci = 0
                ble = BleModule()
                ble.run(hci)
            except Exception as e:  # noqa: BLE001
                debug("critical", str(e))
        elif choice.lower() == "7" or choice.lower() == "bluetooth":
            if 'bluetooth' not in globals() or not bluetooth:
                debug("critical", "Bluetooth module not loaded")
                return False
            bt = bluetooth()
            bt.run()
        elif choice.lower() == "module":
            debug("debug", "Not sure what you want, goodbye")
            sys.exit(0)
        elif choice == "0":
            debug("critical", "Exiting...")
            return True
        else:
            debug("error", "Invalid choice")
            return False
        
    except KeyboardInterrupt:
        debug("warn", "Raised KeyboardInterrupt! Goodbye!")
        sys.exit()
    except Exception as e:  # noqa: BLE001
        debug("critical", f"Fatal error: {e}")
        return False

if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        print("CryWirelessMV — WiFi & BLE Penetration Testing Tool")
        print("Usage: sudo python main.py")
        print()
        print("Options:")
        print("  -h, --help     Show this help message")
        sys.exit(0)
    else:
        startup()