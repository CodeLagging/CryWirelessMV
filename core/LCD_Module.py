# LCD_Module.py


# here lies the lcd module, completely removed
# cuz it takes space with no one even using an lcd
# but hey it dosent suck that bad :D (maybe it does)


import sys
import os


parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

#from RPLCD.i2c import CharLCD
import time
#lcd = CharLCD('PCF8574', 0x27, cols=16, rows=2)

def clear_display():
    #lcd.clear()
    pass

def display_message(message, row, duration=None):
    #lcd.cursor_pos = (row, 0)
    #lcd.write_string(message.ljust(16))
    if duration:
        time.sleep(duration)
        #lcd.clear()

def standby_message():
    clear_display()
    display_message(" CryWireless V2 ", 0)
    display_message("  Standby Mode  ", 1)