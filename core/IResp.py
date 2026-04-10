# IResp.py
import os
import sys
import serial
import serial.tools.list_ports
import time
from pathlib import Path
import configparser
import platform
import shutil


parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from debugs import debug

LCD_AVAILABLE = False
try:
    global standby_message
    from core.LCD_Module import display_message, clear_display, standby_message
    LCD_AVAILABLE = True
except ImportError:
    try:
        from LCD_Module import display_message, clear_display, standby_message
        LCD_AVAILABLE = True
    except ImportError:
        display_message = lambda msg, row, duration=None: None
        clear_display = lambda: None

class IRExplorer:
    def __init__(self):
        self.current_path = Path.cwd()
        self.serial_port = None
        self.baudrate = 115200
        self.config_file = Path.cwd() / "ir_explorer.conf"
        self.config = self.load_config()
        self.database = Path(self.config.get('database', str(Path.cwd())))
        self.is_windows = platform.system() == "Windows"
        self.in_browser = False

    def load_config(self):
        config = {
            'database': str(Path.cwd()),
            'serial_timeout': '3.0',
            'exec_all_delay': '1.0',
            'serial_port': ''
        }
        if self.config_file.exists():
            try:
                parser = configparser.ConfigParser()
                parser.read(self.config_file)
                if 'DEFAULT' in parser:
                    loaded_config = dict(parser['DEFAULT'])
                    config.update(loaded_config)
                debug("ok", f"Loaded config: {self.config_file}")
            except Exception as e:
                debug("error", f"Config load error: {e}")
        return config

    def save_config(self):
        try:
            parser = configparser.ConfigParser()
            parser['DEFAULT'] = self.config
            with open(self.config_file, 'w') as f:
                parser.write(f)
            debug("ok", f"Config saved: {self.config_file}")
        except Exception as e:
            debug("error", f"Config save error: {e}")

    def get_terminal_width(self):
        try:
            return shutil.get_terminal_size().columns
        except:
            return 80

    def display_items_multi_column(self, items):
        if not items:
            return

        term_width = self.get_terminal_width()
        item_texts = []
        for i, (item_type, name, path) in enumerate(items):
            marker = "[DIR]" if item_type == 'folder' else "[IR ]"
            item_text = f"{i+1:2d}. {marker} {name}"
            item_texts.append(item_text)

        max_width = max(len(text) for text in item_texts)
        item_width = max(20, max_width + 2)
        columns = max(1, (term_width // item_width))
        rows = (len(items) + columns - 1) // columns
        padded_items = [text.ljust(item_width) for text in item_texts]

        for r in range(rows):
            row_items = []
            for c in range(columns):
                idx = c * rows + r
                if idx < len(padded_items):
                    row_items.append(padded_items[idx])
                else:
                    row_items.append(' ' * item_width)
            print(' '.join(row_items))

    def get_serial_port_name(self, port_info):
        if self.is_windows:
            return port_info.device
        return port_info.device.replace('/dev/', '')

    def format_serial_path(self, short_name):
        if self.is_windows:
            return short_name
        return f'/dev/{short_name}'

    def open_serial_port(self, port_path, save=False):
        try:
            if LCD_AVAILABLE:
                clear_display()
                display_message("Connecting to", 0)
                display_message(f"{port_path[:14]}", 1)
            
            if self.serial_port and self.serial_port.is_open:
                self.serial_port.close()
            self.serial_port = serial.Serial(port_path, self.baudrate, timeout=1)
            if not self.is_windows:
                self.serial_port.write(b'\n\n\n')
                time.sleep(0.5)
                self.serial_port.reset_input_buffer()
            debug("ok", f"Opened {port_path}")
            if LCD_AVAILABLE:
                display_message("  Connected!  ", 0)
                display_message(f"{port_path[:14]}", 1)
                time.sleep(2)
            if save:
                self.config['serial_port'] = port_path
                self.save_config()
            return True
        except Exception as e:
            debug("error", f"Failed {port_path}: {e}")
            if LCD_AVAILABLE:
                display_message(" Serial Error ", 0)
                display_message("Check Device", 1)
                time.sleep(2)
            self.serial_port = None
            return False

    def get_serial_port_name_from_path(self, port_path):
        return port_path.replace('/dev/', '') if not self.is_windows else port_path

    def select_serial_port(self, save=False):
        ports = serial.tools.list_ports.comports()
        if not ports:
            debug("error", "No serial ports!")
            return False

        debug("info", "Serial ports:")
        for i, port in enumerate(ports):
            print(f"{i+1:2d}. {port.device}")

        current = self.config.get('serial_port', '')
        if current:
            print(f" D. {current} (default)")

        while True:
            choice = input("Select/D/0 skip: ").strip().upper()
            if choice == '0':
                return False
            try:
                if choice == 'D' and current:
                    return self.open_serial_port(current, save)
                idx = int(choice) - 1
                if 0 <= idx < len(ports):
                    return self.open_serial_port(ports[idx].device, save)
            except:
                pass
        return False

    def reconnect_serial(self):
        serial_port = self.config.get('serial_port', '')
        if serial_port:
            return self.open_serial_port(serial_port)
        return False

    def parse_ir_file(self, file_path):
        functions = []
        current_func = {}
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    if line.startswith('name:'):
                        if current_func:
                            functions.append(current_func)
                        current_func = {'name': line.split(':', 1)[1].strip()}
                    elif line.startswith('type:'):
                        current_func['type'] = line.split(':', 1)[1].strip()
                    elif line.startswith('protocol:'):
                        current_func['protocol'] = line.split(':', 1)[1].strip()
                    elif line.startswith('address:'):
                        current_func['address'] = line.split(':', 1)[1].strip()
                    elif line.startswith('command:'):
                        current_func['command'] = line.split(':', 1)[1].strip()
                    elif line.startswith('frequency:'):
                        current_func['frequency'] = line.split(':', 1)[1].strip()
                    elif line.startswith('duty_cycle:'):
                        current_func['duty_cycle'] = line.split(':', 1)[1].strip()
                    elif line.startswith('data:'):
                        current_func['data'] = line.split(':', 1)[1].strip()
                
                if current_func:
                    functions.append(current_func)
                    
        except Exception as e:
            debug("error", f"Parse error {file_path}: {e}")
        
        return functions

    def list_directory(self, path):
        items = []
        path_obj = Path(path)
        if not path_obj.exists():
            return []

        for item in sorted(path_obj.iterdir()):
            if item.is_dir():
                items.append(('folder', item.name, item))

        for item in sorted([i for i in path_obj.iterdir() if i.suffix == '.ir']):
            items.append(('file', item.name, item))

        return items

    def send_ir_command(self, func):
        if not self.serial_port or not self.serial_port.is_open:
            if not self.reconnect_serial():
                debug("error", "No serial!")
                return False

        if func.get('type') == 'parsed':
            protocol = func.get('protocol', '').lower()
            address = func.get('address', '').replace(' ', '')
            command = func.get('command', '').replace(' ', '')
            send_cmd = f"send {protocol} {address} {command}\n"
            
        elif func.get('type') == 'raw':
            frequency = func.get('frequency', '38000')
            duty_cycle = func.get('duty_cycle', '0.33')
            data = func.get('data', '')
            send_cmd = f"raw {frequency} {duty_cycle} {data}\n"
            
        else:
            debug("error", f"Unknown type: {func.get('type')}")
            return False

        try:
            debug("info", f"Sending: {send_cmd[:80].strip()}..." if len(send_cmd) > 80 else f"Sending: {send_cmd.strip()}")
            if LCD_AVAILABLE:
                clear_display()
                display_message("  Sending IR  ", 0)
                display_message(f"{func['name'][:14]}", 1)
            
            self.serial_port.write(send_cmd.encode())
            
            timeout = float(self.config.get('serial_timeout', '3.0'))
            start_time = time.time()
            response_lines = []
            
            while time.time() - start_time < timeout:
                if self.serial_port.in_waiting > 0:
                    chunk = self.serial_port.read(self.serial_port.in_waiting).decode(errors='ignore')
                    response_lines.append(chunk)
                    if 'OK' in chunk or 'ERROR' in chunk:
                        break
                time.sleep(0.05)
            
            if response_lines:
                response = ''.join(response_lines).strip()
                debug("ok", f"Response: {response}")
                if LCD_AVAILABLE:
                    if 'OK' in response:
                        display_message("   IR Sent!   ", 0)
                        display_message("      OK      ", 1)
                    else:
                        display_message("   IR Error   ", 0)
                        display_message("  Check Log  ", 1)
                    time.sleep(1)
                return 'OK' in response
            else:
                debug("warn", "No response received")
                if LCD_AVAILABLE:
                    display_message(" No Response ", 0)
                    display_message("  Timeout!   ", 1)
                    time.sleep(1)
                return False
                
        except Exception as e:
            debug("error", f"Send error: {e}")
            if LCD_AVAILABLE:
                display_message(" Send Error  ", 0)
                display_message(" Check Log  ", 1)
                time.sleep(1)
            return False

    def execute_all_functions(self, functions):
        delay = float(self.config.get('exec_all_delay', '1.0'))
        debug("info", f"Executing {len(functions)} functions (delay: {delay}s)")
        if LCD_AVAILABLE:
            clear_display()
            display_message("Executing All", 0)
            display_message(f"{len(functions)} functions ", 1)
            time.sleep(2)
        
        success = 0
        for i, func in enumerate(functions, 1):
            debug("info", f"[{i}/{len(functions)}] {func['name']}")
            if self.send_ir_command(func):
                success += 1
            if i < len(functions):
                time.sleep(delay)
        debug("ok", f"Completed: {success}/{len(functions)}")
        if LCD_AVAILABLE:
            clear_display()
            display_message("   Complete!  ", 0)
            display_message(f" {success}/{len(functions)} sent ", 1)
            time.sleep(2)
            standby_message()
            

    def copy_command(self, func):
        if func.get('type') == 'parsed':
            protocol = func.get('protocol', '').lower()
            address = func.get('address', '').replace(' ', '')
            command = func.get('command', '').replace(' ', '')
            copy_text = f"send {protocol} {address} {command}"
        elif func.get('type') == 'raw':
            frequency = func.get('frequency', '38000')
            duty_cycle = func.get('duty_cycle', '0.33')
            data = func.get('data', '')
            copy_text = f"raw {frequency} {duty_cycle} {data}"
        else:
            debug("error", "Unknown type!")
            return
            
        debug("ok", f"Copied: {copy_text[:80]}..." if len(copy_text) > 80 else f"Copied: {copy_text}")
        try:
            import pyperclip
            pyperclip.copy(copy_text)
            debug("ok", "Clipboard OK")
        except:
            pass

    def handle_config_command(self, cmd):
        if cmd.startswith('config '):
            parts = cmd[7:].split(maxsplit=1)
            if len(parts) == 2:
                key, value = parts
                key = key.lower()
                value = value.strip().strip('"').strip("'")
                
                if key == 'serial_port':
                    if self.open_serial_port(value, save=True):
                        debug("ok", f"Serial port: {value}")
                elif key == 'database':
                    db_path = Path(value)
                    if db_path.exists() and db_path.is_dir():
                        self.database = db_path.absolute()
                        self.config['database'] = str(self.database)
                        self.save_config()
                        debug("ok", f"Database: {self.database}")
                    else:
                        debug("error", "Directory does not exist!")
                elif key == 'serial_timeout':
                    try:
                        timeout = float(value)
                        if timeout > 0:
                            self.config['serial_timeout'] = str(timeout)
                            self.save_config()
                            debug("ok", f"Serial timeout: {timeout}s")
                        else:
                            debug("error", "Timeout must be positive!")
                    except:
                        debug("error", "Invalid timeout value!")
                elif key == 'exec_all_delay':
                    try:
                        delay = float(value)
                        if delay >= 0:
                            self.config['exec_all_delay'] = str(delay)
                            self.save_config()
                            debug("ok", f"Exec delay: {delay}s")
                        else:
                            debug("error", "Delay must be non-negative!")
                    except:
                        debug("error", "Invalid delay value!")
                else:
                    debug("error", f"Unknown setting: {key}")
                    print("Available: serial_port, database, serial_timeout, exec_all_delay")
            else:
                debug("error", "Usage: config <setting> <value>")
                print("Example: config serial_port COM3")
                print("Example: config database /path/to/IR_Database")

    def run(self):
        if not self.config_file.exists():
            debug("info", "First Time Setup")
            if LCD_AVAILABLE:
                clear_display()
                display_message(" First Setup ", 0)
                display_message("   IResp...   ", 1)
                time.sleep(2)
            
            db_input = input(f"Database path [{self.database}]: ").strip()
            if db_input:
                db_path = Path(db_input)
                if db_path.exists() and db_path.is_dir():
                    self.database = db_path.absolute()
                    self.config['database'] = str(self.database)
                else:
                    debug("warn", "Path doesn't exist, using current directory")
            
            debug("info", "Serial port setup:")
            self.select_serial_port(save=True)
            
            self.save_config()
            debug("ok", "Setup complete!")
        else:
            serial_port = self.config.get('serial_port', '')
            if serial_port:
                debug("info", f"Connecting to {serial_port}...")
                self.open_serial_port(serial_port)

        debug("info", "IR Explorer")
        print("===========")
        print(f"Config: {self.config_file}")
        print(f"OS: {'Windows' if self.is_windows else 'Linux'}")
        print(f"Database: {self.database}")
        print(f"Serial timeout: {self.config.get('serial_timeout', '3.0')}s")
        print(f"Exec delay: {self.config.get('exec_all_delay', '1.0')}s")
        serial_port = self.config.get('serial_port', 'Not set')
        print(f"Serial port: {serial_port}")
        if self.serial_port and self.serial_port.is_open:
            debug("ok", "Serial status: Connected")
        else:
            debug("warn", "Serial status: Disconnected")
        print("")

        self.current_path = self.database

        while True:
            try:
                if not self.in_browser:
                    cmd = input("Controller-Root: ").strip()
                    if cmd == "exit":
                        break
                    elif cmd == "start":
                        self.in_browser = True
                        self.current_path = self.database
                        if LCD_AVAILABLE:
                            clear_display()
                            display_message("  IResp Mode  ", 0)
                            display_message("   Browsing   ", 1)
                            time.sleep(1)
                        continue
                    elif cmd.startswith("config "):
                        self.handle_config_command(cmd)
                        continue
                    elif cmd == "config":
                        debug("info", "Current Configuration:")
                        print(f"  database = {self.config.get('database', 'Not set')}")
                        print(f"  serial_port = {self.config.get('serial_port', 'Not set')}")
                        print(f"  serial_timeout = {self.config.get('serial_timeout', '3.0')}")
                        print(f"  exec_all_delay = {self.config.get('exec_all_delay', '1.0')}")
                        print("\nUsage: config <setting> <value>")
                        print("Example: config serial_port COM3")
                        continue
                    elif cmd.startswith("script "):
                        script_name = cmd.split(" ",1)[1]
                        if script_name == "off_samsung":
                            if self.serial_port:
                                self.serial_port.write(b"off_samsung\n")
                        if script_name == "list_protocols":
                            os.system("python /scripts/list_protocols.py")
                        continue
                    else:
                        debug("error", "Unknown command!")
                        print("Available commands:")
                        print("  start  - Browse IR database")
                        print("  config - Show current settings")
                        print("  config <setting> <value> - Change setting")
                        print("  script <name> - Run custom script")
                        print("  exit   - Quit program")
                        continue

                items = self.list_directory(self.current_path)
                if not items:
                    debug("warn", "No folders or .ir files!")
                    input("Press Enter...")
                    if self.current_path != self.database:
                        self.current_path = self.current_path.parent
                    else:
                        self.in_browser = False
                    continue

                print(f"\n--- {self.current_path} ---")
                self.display_items_multi_column(items)
                print("  0. Back" if self.current_path != self.database else "  0. Exit")
                choice = input("\nSelect: ").strip()

                if choice == '0':
                    if self.current_path == self.database:
                        self.in_browser = False
                        if LCD_AVAILABLE:
                            clear_display()
                            display_message("  Exit IResp  ", 0)
                            display_message("  Browser...  ", 1)
                            time.sleep(1)
                    else:
                        self.current_path = self.current_path.parent
                    continue

                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(items):
                        item_type, name, path = items[idx]
                        if item_type == 'folder':
                            self.current_path = path
                        else:
                            functions = self.parse_ir_file(path)
                            if not functions:
                                debug("error", "No valid functions!")
                                input("Press Enter...")
                                continue
                            debug("ok", f"Functions in {name}:")
                            for i, func in enumerate(functions, 1):
                                func_type = func.get('type', 'unknown')
                                if func_type == 'parsed':
                                    protocol = func.get('protocol', 'N/A')
                                    print(f"{i:2d}. {func['name']} ({protocol})")
                                elif func_type == 'raw':
                                    print(f"{i:2d}. {func['name']} (RAW)")
                                else:
                                    print(f"{i:2d}. {func['name']} (unknown)")
                            print("  0. Back")
                            print("  A. Execute All")
                            func_choice = input("Select/A: ").strip().upper()
                            if func_choice == '0':
                                continue
                            elif func_choice == 'A':
                                self.execute_all_functions(functions)
                                input("\nPress Enter...")
                                continue
                            else:
                                try:
                                    func_idx = int(func_choice) - 1
                                    if 0 <= func_idx < len(functions):
                                        func = functions[func_idx]
                                        debug("info", f"{func['name']}")
                                        print(f"Name: {func.get('name','N/A')}")
                                        print(f"Type: {func.get('type','N/A')}")
                                        if func.get('type') == 'parsed':
                                            print(f"Protocol: {func.get('protocol','N/A')}")
                                            print(f"Address: {func.get('address','N/A')}")
                                            print(f"Command: {func.get('command','N/A')}")
                                        elif func.get('type') == 'raw':
                                            print(f"Frequency: {func.get('frequency','N/A')}")
                                            print(f"Duty Cycle: {func.get('duty_cycle','N/A')}")
                                            data_preview = func.get('data', 'N/A')[:50]
                                            print(f"Data: {data_preview}..." if len(func.get('data', '')) > 50 else f"Data: {data_preview}")
                                        print("\n1. Send | 2. Copy | 0. Back")
                                        opt = input("Choose: ").strip()
                                        if opt == '1':
                                            self.send_ir_command(func)
                                        elif opt == '2':
                                            self.copy_command(func)
                                        input("\nPress Enter...")
                                except ValueError:
                                    debug("error", "Invalid selection!")
                                    input("Press Enter...")
                except ValueError:
                    debug("error", "Enter a valid number!")
                    input("Press Enter...")
            except KeyboardInterrupt:
                debug("warn", "Exiting...")
                break
            except Exception as e:
                debug("critical", f"Error: {e}")
                input("Press Enter...")
                if self.serial_port and self.serial_port.is_open:
                    self.serial_port.close()


if __name__ == "__main__":
    debug("info", "CryWireless V2 - IR Explorer Module")
    explorer = IRExplorer()
    explorer.run()