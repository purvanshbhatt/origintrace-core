import socket
import subprocess
import os
import ctypes
import sys

def main():
    print("Mock Dropper Execution Started.")
    print("This is a completely benign script for testing the OriginTrace analysis pipeline.")
    
    # High-Value Strings (Static Indicators)
    C2_URL = "http://malicious.c2/drop"
    NPM_PAYLOAD = "npm install hidden-miner"
    PERSISTENCE_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    
    print("Loaded static indicators for analysis.")
    
    # Fake Windows API Calls (Mocking)
    # Define but DO NOT execute pointers to simulate process injection.
    if os.name == 'nt':
        try:
            # We just reference the functions to ensure they appear in the import table / strings
            kernel32 = ctypes.windll.kernel32
            VirtualAlloc_ptr = kernel32.VirtualAlloc
            CreateThread_ptr = kernel32.CreateThread
            print("Defined mock pointers to VirtualAlloc and CreateThread.")
        except AttributeError:
            pass
            
    print("Mock Dropper finished execution safely. Exiting.")
    sys.exit(0)

if __name__ == "__main__":
    main()
