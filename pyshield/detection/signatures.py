"""
Baza potpisa poznatih malwera,
Za sada cu koristiti obicnu python dictionary strukturu
Kasnije ovo mozemo prebaciti u JSON SQLite ili online api
"""

KNOWN_SIGNATURES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty.File.Test",
    "a95be566eb1ff9170dba63f4bb929df80d9f362d7b37b66a12e0ed91e53f4a5e": "Test.Malware.Demo",
}

def is_malware(file_hash):
    """
    Proverava da li dati hash postoji u bazi poznatih malwera
    """

    if file_hash in KNOWN_SIGNATURES:
        return True, KNOWN_SIGNATURES[file_hash]
    return False, None

def get_signature_count():
    """
    Vraca broj poznatih potpisa u bazi"""
    return len(KNOWN_SIGNATURES)