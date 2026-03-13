"""
Glavni skener za proveru fajlova, i da li sadrzi malwer
"""

from pyshield.core.hasher import calculate_sha256
from pyshield.detection.signatures import is_malware

def scan_file(file_path):
    """
    Skenira jedan fajl i vraca rezultat
    """

    file_hash = calculate_sha256(file_path)

    #Ako fajl ne postoji onda ovde vracam informacije 
    if file_hash is None:
        return {
            "file_path": file_path,
            "status": "error",
            "message": "File not found",
            "hash": None,
            "is_malware": False,
            "malware_name": None,
        }

    #u suportnom ako postoji malware
    detected, malware_name = is_malware(file_hash)

    return {
        "file_path": file_path,
        "status": "scanned",
        "message": "File scanned successfully",
        "hash": file_hash,
        "is_malware": detected,
        "malware_name": malware_name,
    }