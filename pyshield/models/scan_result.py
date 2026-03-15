from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FileScanResult:
    file_path: str
    status: str
    message: str
    hash: Optional[str]
    is_malware: bool
    malware_name: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DirectoryScanResult:
    status: str
    message: str
    directory_path: str
    total_files: int
    malware_detected: int
    skipped_files: int
    clean_files: int
    errors: int
    results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
from dataclasses import dataclass,asdict,field
from typing import List, Optional, Dict, Any

from dataclasses import dataclass, asdict, field
from typing import Optional, List, Dict, Any


@dataclass
class FileScanResult:
    file_path: str
    status: str
    message: str
    hash: Optional[str]
    is_malware: bool
    malware_name: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DirectoryScanResult:
    status: str
    message: str
    directory_path: str
    total_files: int
    malware_detected: int
    skipped_files: int
    clean_files: int
    errors: int
    results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
