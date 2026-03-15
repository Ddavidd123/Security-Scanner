import argparse
from pyshield.core.scanner import scan_file, scan_directory
import json
import sys

def main():
    parser = argparse.ArgumentParser(description='PyShield Antivirus CLI')
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    parser.add_argument("--json", action="store_true", help="Print result as JSON")

    file_parser = subparsers.add_parser('scan-file', help='Scan a single file for malware')
    file_parser.add_argument('path', help='Path to the file to scan')

    dir_parser = subparsers.add_parser('scan-dir', help='Scan a directory for malware')
    dir_parser.add_argument('path', help='Path to the directory to scan')
    dir_parser.add_argument("--max-size-mb", type=int, default=25, help="Max file size to scan")

    dir_parser.add_argument(
        "--ext",
        nargs="*",
        default=None,
        help="Allowed extensions, example: .exe .dll .ps1 .js",
    )

    args = parser.parse_args()

    if args.command == "scan-file":
        result = scan_file(args.path)
        

        if args.json:
            print(json.dumps(result, indent=2,ensure_ascii=False))
        else:
            print_file_report(result)

        sys.exit(get_exit_code(result))

    elif args.command == "scan-dir":
        extensions = set(args.ext) if args.ext else None
        result = scan_directory(
            args.path,
            allowed_extensions=extensions,
            max_file_size_mb=args.max_size_mb,
        )
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print_directory_report(result)

        sys.exit(get_exit_code(result))

def print_file_report(result):
    print("\n== Pyshield File Scan Report ==")
    print(f"File: {result['file_path']}")
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"SHA-256: {result['hash']}")

    if result["is_malware"]:
        print(f"Threat: DETECTED ({result['malware_name']})")
    else:
        print("Threat: CLEAN")

def print_directory_report(result):
    print("\n== Pyshield Directory Scan Report ==")
    print(f"Directory: {result['directory_path']}")
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Files Scanned: {result['total_files']}")
    print(f"Malware Detected: {result['malware_detected']}")
    print(f"Clean Files: {result['clean_files']}")
    print(f"Skipped Files: {result['skipped_files']}")
    print(f"Errors: {result['errors']}")

    malware_items = [r for r in result["results"] if r["is_malware"]]

    if malware_items:
        print("\nDetected threats:")
        for item in malware_items:
            print(f"- {item['file_path']} -> {item['malware_name']}")
    else:
        print("\nDetected threats: none")

def get_exit_code(result):
    if result.get("status") == "error":
        return 2

    if result.get("is_malware") is True:
        return 1

    if result.get("malware_detected", 0) > 0:
        return 1

    return 0
    
if __name__ == "__main__":
    main()