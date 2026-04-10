# main.py
import os
import sys
from time import sleep as wait
from colorama import Fore, Style, init
init()

def startup():
    global debug, banner, WiFiAttackModule, HandshakeCaptureModule, IRExplorer
    
    # And here lies random shit i pulled from stackoverflow
    # that i changed a bit to make it work in this shit code i made
    # to make it work on sudo or venv cuz it dosent
    script_dir = os.path.dirname(os.path.abspath(__file__))
    core_dir = os.path.join(script_dir, 'core')
    core_path = os.path.abspath(core_dir)
    script_path = os.path.abspath(script_dir)
    for path in [core_path, script_path]:
        if path not in sys.path:
            sys.path.insert(0, path)
    venv_path = os.path.join(script_dir, 'venv')
    if os.path.exists(venv_path) and os.geteuid() == 0:  # Running as root (sudo)
        venv_site_packages = os.path.join(venv_path, 'lib')
        if os.path.exists(venv_site_packages):
            for lib_dir in os.listdir(venv_site_packages):
                site_pkg = os.path.join(venv_site_packages, lib_dir, 'site-packages')
                if os.path.exists(site_pkg) and site_pkg not in sys.path:
                    sys.path.insert(0, site_pkg)
    existing_pythonpath = os.environ.get('PYTHONPATH', '')
    additional_paths = os.pathsep.join([core_path, script_path])
    if existing_pythonpath:
        os.environ['PYTHONPATH'] = f"{additional_paths}{os.pathsep}{existing_pythonpath}"
    else:
        os.environ['PYTHONPATH'] = additional_paths
    # AND IT STILL DOSENT WORK (or maybe it does)


    # Is there even a better way to do this?
    # cuz i know this is type shit
    try:
        import banner
        from debugs import debug
        debug("info", "Core Modules Loaded")
        if os.path.exists(core_dir):
            debug("ok", f"Core directory: {core_dir}")
    # Cool fallback cuz theres always one broken installation on someone's system
    except ImportError as critical:
        print(f"{Fore.RED}[CRITICAL]: Core Module {critical.name}.py is missing{Style.RESET_ALL}")
        exit(1)
    
    missing = [] # i wonder why its missing :D
    try: 
        from core.wifi_module import WiFiAttackModule
        globals()['WiFiAttackModule'] = WiFiAttackModule
    except ImportError: 
        WiFiAttackModule = None
        missing.append("wifi") # Why would wifi be missing, thats the whole point of this

    # here lies a placeholder for ble_module.py
    # here lies a placeholder for bt_module.py
    # they both fucking suck. removed.
    # leave no trace of that trash code.

    # hmm shouldnt i just make it disabled by default
    # instead of removing? nah they both still suck asf
    
    try: 
        from core.handshake_module import HandshakeCaptureModule
        globals()['HandshakeCaptureModule'] = HandshakeCaptureModule
    except ImportError: 
        HandshakeCaptureModule = None
        missing.append("handshake") # youll love this, dont leave it
    
    try: 
        from core.IResp import IRExplorer
        globals()['IRExplorer'] = IRExplorer
    except ImportError: 
        IRExplorer = None
        missing.append("iresp") # do you even have the iresp? no cuz i never released it :D
    
    if missing == ['wifi', 'handshake', 'iresp']: # why would you even have none. what are you doing.
        debug("critical", "No attack modules available. Exiting.")
        exit(1)
    if missing:
        debug("warn", "Core Modules Limited:")
        for i in missing:
            debug("warn", f"Core Module '{i}' unavailable.")
    else: debug("ok", "All modules loaded")
    
    # oh why would you want to quit? go back and shutdown some random wifi
    # preferrably one with people playing ranked games :D
    should_exit = main()
    return should_exit


# the fuck is this, why not shove cli_mode in here?
# cuz i have no fucking idea why.. im just lazy fr
def main():
    try:
        banner.check_os() # no there is no fucking windows or wsl support
        wait(3)
        os.system("clear")
        banner.print_banner()
        
        # Main menu loop
        while True:
            if cli_mode():
                break
    # ofcourse you need these, or maybe not
    # i dont care, youll have it anyway
    except KeyboardInterrupt:
        debug("warn", "Interrupted by user")
        return False
    except Exception as e:
        debug("critical", f"Fatal error: {e}")
        return False



# Just cuz its named cli_mode doesnt mean ill add a "gui_mode" later.
# i tried before, its a nightmare. never touhing that again.
def cli_mode():
    try:
        # oooh now shutdown some kid's router, preferrably one in a ranked game
        print("\nSelect Module:")
        if 'WiFiAttackModule' in globals() and WiFiAttackModule:
            print("1. WiFi Attack Module")
        if 'HandshakeCaptureModule' in globals() and HandshakeCaptureModule:
            print("2. Handshake Capture Module")
        if 'IRExplorer' in globals() and IRExplorer:
            print("3. IR Explorer Module")
        print("0. Exit")
        
        choice = input("\nModule: ").strip()
        
        if choice == "1" or choice.lower() == "wifi":
            if 'WiFiAttackModule' not in globals() or not WiFiAttackModule:
                debug("critical", "WiFi module not loaded")
                return False
            wifi = WiFiAttackModule()
            wifi.run()
            return False
        
        # here lies a placeholder for ble_module.py
        # here lies a placeholder for bt_module.py
        # they both fucking suck. removed.
        
        # does not use mdk4, so no its not on wifi_module.py
        # and i have no fucking idea why this is here
        elif choice == "2" or choice.lower() == "handshake":
            if 'HandshakeCaptureModule' not in globals() or not HandshakeCaptureModule:
                debug("critical", "Handshake Capture module not loaded")
                return False
            hc = HandshakeCaptureModule()
            hc.run()
            return False
        
        # like you have the iresp code anyway lmao
        elif choice == "3" or choice.lower() == "iresp" or choice.lower() == "ir":
            if 'IRExplorer' not in globals() or not IRExplorer:
                debug("critical", "IR Explorer module not loaded")
                return False
            ir = IRExplorer()
            ir.run()
            return False
        
        elif choice == "0":
            debug("info", "Exiting...")
            return True
        else:
            debug("error", "Invalid choice")
            return False
    
    except KeyboardInterrupt:
        debug("warn", "Interrupted by user")
        return False
    except Exception as e:
        debug("critical", f"Fatal error: {e}")
        return False

if __name__ == "__main__":
    startup()