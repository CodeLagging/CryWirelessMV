# debugs.py
from colorama import Fore, Style, init
init()
message_types = {
    'error' : f'{Fore.RED}[ERR]: {Style.RESET_ALL}',
    'info' : f'{Fore.CYAN}[INFO]: {Style.RESET_ALL}',
    'warn' : f'{Style.BRIGHT}{Fore.LIGHTYELLOW_EX}[WARN]: {Style.RESET_ALL}',
    'ok' : f'{Fore.LIGHTGREEN_EX}[OK]: {Style.RESET_ALL}',
    'debug' : f'{Fore.MAGENTA}[DEBUG]: {Style.RESET_ALL}',
    'critical' : f'{Fore.RED}{Style.BRIGHT}[CRITICAL]:',
}

def debug(type, message):
    if type.lower() == "critical":
        print(f'{message_types.get(type.lower())} {message}{Style.RESET_ALL}')
    else:
        print(f'{message_types.get(type.lower())}{message}')

if __name__ == "__main__":
    debug("info", "info, ignore")
    debug("warn", "warn, something wrong")
    debug("error", "err, fix it")
    debug("ok", "ok status")
    debug("debug", "debugging info")
    debug("critical", "critical, could not continue")