"""
Glavni skener za proveru fajlova, i da li sadrzi malwer
"""
import os
from pyshield.core.hasher import calculate_sha256
from pyshield.detection.signatures import is_malware
from pyshield.utils.logger import logger
from pyshield.models.scan_result import FileScanResult, DirectoryScanResult

def scan_file(file_path):
    """
    Skenira jedan fajl i vraca rezultat
    """

    logger.info(f"Starting scan for file: {file_path}")

    file_hash = calculate_sha256(file_path)

    #Ako fajl ne postoji onda ovde vracam informacije 
    if file_hash is None:
        logger.error(f"File not found: {file_path}")

        return FileScanResult(
            file_path=file_path,
            status="error",
            message="File not found",
            hash=None,
            is_malware=False,
            malware_name=None,
        ).to_dict()

    #u suportnom ako postoji malware
    detected, malware_name = is_malware(file_hash)

    if detected:
        logger.warning(f"Malware detected: {malware_name} in file: {file_path}")
    else:
        logger.info(f"No malware detected in file: {file_path}")
    return FileScanResult(
        file_path=file_path,
        status="scanned",
        message="File scanned successfully",
        hash=file_hash,
        is_malware=detected,
        malware_name=malware_name,
    ).to_dict()


def scan_directory(directory_path, allowed_extensions=None, max_file_size_mb=25):
    """
    Skeniranje fajlova u datom direktorijumu 
    """

    logger.info(f"Starting directory scan: {directory_path}")

    if not os.path.isdir(directory_path):
        logger.error(f"Directory not found: {directory_path}")
        return DirectoryScanResult(
            status="error",
            message="Directory not found",
            directory_path=directory_path,
            total_files=0,
            malware_detected=0,
            skipped_files=0,
            clean_files=0,
            errors=1,
            results=[],
        ).to_dict()
    results = []
    skipped = [] # one koje smo preskocili 
    # root koristim ignorisem _ - for root, _, files
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            if should_scan_file(file_path, allowed_extensions, max_file_size_mb):
                result = scan_file(file_path)
                results.append(result)
            else:
                skipped.append(file_path)
    
    malware_detected = sum(1 for r in results if r["is_malware"])
    errors = sum(1 for r in results if r["status"] == "error")
    clean_files = sum(1 for r in results if r["status"] == "scanned" and not r["is_malware"])

    logger.info(
    f"Directory scan completed | scanned={len(results)} "
    f"malware={malware_detected} clean={clean_files} "
    f"errors={errors} skipped={len(skipped)}"
)

    return DirectoryScanResult(
        status="completed",
        message="Directory scan completed",
        directory_path=directory_path,
        total_files=len(results),
        malware_detected=malware_detected,
        skipped_files=len(skipped),
        clean_files=clean_files,
        errors=errors,
        results=results,
    ).to_dict()
def should_scan_file(file_path, allowed_extensions, max_file_size_mb):
    """
    Proverava da li fajl treba da se skenira na osnovu ekstenzije
    """
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    if allowed_extensions is not None and ext not in allowed_extensions:
        return False
    
    file_size_bytes = os.path.getsize(file_path)
    max_size_bytes = max_file_size_mb * 1024 * 1024

    if file_size_bytes > max_size_bytes:
        return False

    return True