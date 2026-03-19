from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from pyshield.core.scanner import scan_directory, scan_file
from pyshield.protection.quarantine import QuarantineManager

#jedan objekat koji ce biti dostupan za sve api zahteve
quarantine_manager = QuarantineManager()

# ============================================================================
# FastAPI Application Setup
# ============================================================================

app = FastAPI(
    title="Security Scanner API",
    version="1.0.0",
    description="Modern security scanner backend API for threat detection",
    docs_url="/docs",
    redoc_url="/redoc",
)


# ============================================================================
# Request Models
# ============================================================================

class FileScanRequest(BaseModel):
    """Schema for file scanning requests."""

    path: str = Field(
        ..., 
        description="Absolute or relative path to the file for scanning"
    )
    quarantine: bool = Field(
        False, 
        description="Auto-quarantine file if malware detected"
    )


class DirectoryScanRequest(BaseModel):
    """Schema for directory scanning requests."""

    path: str = Field(
        ..., 
        description="Absolute or relative path to the directory for scanning"
    )
    max_size_mb: int = Field(
        25, 
        ge=1, 
        le=1024,
        description="Maximum file size threshold in MB"
    )
    ext: list[str] | None = Field(
        default=None,
        description="Allowed extensions (e.g., ['.py', '.exe', '.dll'])"
    )
    quarantine: bool = Field(
        False, 
        description="Auto-quarantine files if malware detected"
    )

class QuarantineRestoreRequest(BaseModel):
    """Schema for quarantine restore requests."""
    
    #jedinstveni identifikator fajla
    item_id: str = Field(
        ...,
        description="ID of quarantined item to restore (from quarantine list)"
    )
    restore_path: str = Field(
        ...,
        description="Where to restore the file"
    )  


# ============================================================================
# Root Endpoint
# ============================================================================

@app.get("/")
def root() -> dict[str, str]:
    """Service info and links to API documentation."""
    return {
        "service": "security-scanner-api",
        "status": "running",
        "message": "Security Scanner - Modern Threat Detection API",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
    }


# ============================================================================
# Health Check Endpoint
# ============================================================================

@app.get("/health")
def health() -> dict[str, str]:
    """Health check endpoint for monitoring and uptime checks."""
    return {
        "status": "ok",
        "service": "security-scanner-api",
    }


# ============================================================================
# Scanning Endpoints
# ============================================================================

@app.post("/scan/file")
def api_scan_file(payload: FileScanRequest) -> dict[str, Any]:
    """
    Scan single file for malware.
    
    Args:
        payload: FileScanRequest with file path and options
        
    Returns:
        Scan result with detection status, hash, and metadata
        
    Raises:
        HTTPException: If file not found or scan fails
    """
    result = scan_file(payload.path)

    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result)

    return result


@app.post("/scan/directory")
def api_scan_directory(payload: DirectoryScanRequest) -> dict[str, Any]:
    """
    Scan directory recursively for malware.
    
    Args:
        payload: DirectoryScanRequest with directory path and filters
        
    Returns:
        Aggregated scan results with threat summary
        
    Raises:
        HTTPException: If directory not found or scan fails
    """
    extensions = set(payload.ext) if payload.ext else None

    result = scan_directory(
        payload.path,
        allowed_extensions=extensions,
        max_file_size_mb=payload.max_size_mb,
    )

    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result)

    return result


# ============================================================================
# Quarantine Management Endpoints
# ============================================================================

@app.get("/quarantine/list")
def quarantine_list() -> dict[str, Any]:
    """
    List all quarantined items.
    
    Returns:
        List of quarantined files with metadata (ID, name, date, threat name)
    """
    items = quarantine_manager.list_items()
    return {
        "status": "ok",
        "items": items,
        "total": len(items),
    }


@app.post("/quarantine/restore")
def quarantine_restore(payload: QuarantineRestoreRequest) -> dict[str, str]:
    """
    Restore a quarantined file.
    
    Args:
        payload: QuarantineRestoreRequest with item ID and restore path
        
    Returns:
        Confirmation message
        
    Raises:
        HTTPException: If item not found or restore fails
    """
    try:
        quarantine_manager.restore_file(
            payload.item_id,
            payload.restore_path
        )
        return {
            "status": "ok",
            "message": f"File restored to {payload.restore_path}",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))