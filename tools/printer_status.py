#!/usr/bin/env python3
"""Read FlashForge Adventurer status over its TCP command port.
As a script: prints a printer JSON fragment for tools/merge-data.js.
As a module: read_printer() returns the same values as a dict."""
import json, os, re, socket, sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))

def load_env(path=os.path.join(HERE, 'printer.env')):
    out = {}
    try:
        for line in open(path):
            if '=' in line and not line.lstrip().startswith('#'):
                k, v = line.split('=', 1); out[k.strip()] = v.strip()
    except OSError:
        pass
    return out

def ask(ip, port, cmd):
    s = socket.create_connection((ip, port), timeout=4)
    s.sendall(cmd + b'\r\n')
    buf = b''
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            buf += c
            if buf.rstrip().endswith(b'ok'): break
    except socket.timeout:
        pass
    s.close()
    return buf.decode(errors='replace')

def grab(pattern, text):
    m = re.search(pattern, text)
    return m.group(1).strip() if m else None

def read_printer(ip=None, port=None):
    env = load_env()
    ip = ip or env.get('PRINTER_IP')
    port = int(port or env.get('PRINTER_PORT', 8899))
    if not ip:
        raise RuntimeError('no printer IP: set PRINTER_IP in tools/printer.env')
    status = ask(ip, port, b'~M119')
    temps = ask(ip, port, b'~M105')
    machine = (grab(r'MachineStatus:[ \t]*(\S+)', status) or 'unknown')
    current = grab(r'CurrentFile:[ \t]*([^\r\n]*)', status) or None
    nozzle = grab(r'T0:\s*([\d.]+)', temps) or grab(r'T:\s*([\d.]+)', temps)
    bed = grab(r'B:\s*([\d.]+)', temps)
    up = machine.upper()
    state = 'printing' if up in ('BUILDING_FROM_SD', 'PRINTING') else ('idle' if 'READY' in up else machine.lower())
    return {
        'name': 'FlashForge Adventurer 5X',
        'status': state,
        'job': current,
        'progress': None,
        'nozzle_temp': float(nozzle) if nozzle else None,
        'bed_temp': float(bed) if bed else None,
        'filament': None,
        'as_of': datetime.now(timezone.utc).isoformat(),
    }

if __name__ == '__main__':
    try:
        p = read_printer(*(sys.argv[1:3]))
    except (OSError, RuntimeError) as e:
        sys.exit(f'printer did not answer: {e}')
    nozzle_key = 'nozzle_c'; bed_key = 'bed_c'
    p[nozzle_key] = p.pop('nozzle_temp'); p[bed_key] = p.pop('bed_temp')
    print(json.dumps({'printer': p}))
