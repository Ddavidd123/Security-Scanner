import psutil
import os
from typing import list, Dict
from pyshield.core.hasher import calculate_sha256
from pyshield.detection.signatures import is_malware

def get_active_processes() -> list[dict]:
    """
    Citanje aktivnih procesa na windowsu,
    vraca listu procesa sa fajl putanjom PID i imenom
    """

    processes = []
    for proc in psutil.process_iter(['pid','name','exe']):
        try:
            #pronalazi gde je exe fajl
            exe_path = proc.info.get('exe')

            #ako nema exe path-a preskace  system process
            if not exe_path or not os.path.exists(exe_path):
                continue

            #dodaje proces u listu
            processes.append({
                'pid': proc.info.get('pid'),
                'name': proc.info.get('name'),
                'exe_path': exe_path
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            #ignorira procese koje ne moze da cita
            continue

    return processes

def scan_processes() -> dict:
    """
    Skenira sve procese za virusom
    i vraca recnik sa rezultatima
    """

    processes = get_active_processes()
    results = {
        'status': 'ok',
        'total_processes': len(processes),
        'clean': [],
        'suspicious': [],
        'malware': []
    }

    for proc in processes:
        exe_path = proc['exe_path']
        exe_hash = calculate_sha256(exe_path)

        if not exe_hash:
            continue

        #provera da li je malware
        is_malicious, malware_name = is_malware(exe_hash)

        process_info = {
            'pid': proc['pid'],
            'name': proc['name'],
            'exe_path': exe_path,
            'hash': exe_hash,
        }

        if is_malicious:
            process_info['threat'] = malware_name
            results['malware'].append(process_info)
        else:
            results['clean'].append(process_info)
    
    return results
