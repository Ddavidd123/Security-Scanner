"""
Modul za izracunavanje hash vrednosti fajlova
Hash- predstavlja otisak prsta fajla - string koji identifikuje
sadrzaj fajla
"""

import hashlib

def calculate_sha256(file_path):
    """ Calculates sha256 hash of a file 
    
    Args:
        file_path (str): Path to the file to be hashed
    
    Returns:
        str: The sha256 hash of the file
    """

    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""): ##lambda predstavlja anonimnu fju koja cita fajl
                sha256_hash.update(chunk) #vracamo hash kao hex string 
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

 
