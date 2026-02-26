import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Set

logger = logging.getLogger(__name__)


@dataclass
class DocumentRecord:
    doc_id: str
    filename: str
    sha256_hash: str
    source: str
    uploaded_by: str
    upload_timestamp: str
    size_bytes: int
    content_type: str
    trusted: bool = False
    tags: List[str] = field(default_factory=list)


@dataclass
class ProvenanceResult:
    is_valid: bool
    doc_id: str
    reason: str
    record: "DocumentRecord | None" = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "threat_type": "provenance_validation",
            "detected_by": "provenance_validator",
            "action_taken": "allowed" if self.is_valid else "blocked",
            "reason": self.reason,
            "doc_id": self.doc_id,
        }


class ProvenanceValidator:
    def __init__(self, allowed_content_types: Set[str] | None = None, max_file_size_bytes: int = 10 * 1024 * 1024, allowed_sources: Set[str] | None = None):
        self.allowed_content_types = allowed_content_types or {"application/pdf"}
        self.max_file_size_bytes = max_file_size_bytes
        self.allowed_sources = allowed_sources
        self._records: dict[str, DocumentRecord] = {}
        self._known_hashes: dict[str, str] = {}
        self._audit_log: List[dict] = []

    def compute_hash(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def register_document(self, content: bytes, filename: str, source: str = "user_upload", uploaded_by: str = "anonymous", content_type: str = "application/pdf", tags: List[str] | None = None) -> ProvenanceResult:
        """
        Validate and register a document for ingestion.

        Checks:
            1. Content type is allowed
            2. File size is within limits
            3. Source is trusted (if whitelist is set)
            4. Document is not a duplicate

        Returns a ProvenanceResult indicating if ingestion should proceed.
        """
        sha256 = self.compute_hash(content)
        doc_id = sha256[:16]

        if content_type not in self.allowed_content_types:
            return ProvenanceResult(
                is_valid=False,
                doc_id=doc_id,
                reason=f"Content type '{content_type}' not allowed. Allowed: {self.allowed_content_types}",
            )

        if len(content) > self.max_file_size_bytes:
            return ProvenanceResult(
                is_valid=False,
                doc_id=doc_id,
                reason=f"File size {len(content)} bytes exceeds limit of {self.max_file_size_bytes} bytes",
            )

        if self.allowed_sources is not None and source not in self.allowed_sources:
            return ProvenanceResult(
                is_valid=False,
                doc_id=doc_id,
                reason=f"Source '{source}' not in allowed sources: {self.allowed_sources}",
            )

        if sha256 in self._known_hashes:
            existing_id = self._known_hashes[sha256]
            return ProvenanceResult(
                is_valid=False,
                doc_id=doc_id,
                reason=f"Duplicate document. Matches existing doc_id: {existing_id}",
                record=self._records.get(existing_id),
            )

        trusted = self.allowed_sources is not None and source in self.allowed_sources
        record = DocumentRecord(
            doc_id=doc_id,
            filename=filename,
            sha256_hash=sha256,
            source=source,
            uploaded_by=uploaded_by,
            upload_timestamp=datetime.now(timezone.utc).isoformat(),
            size_bytes=len(content),
            content_type=content_type,
            trusted=trusted,
            tags=tags or [],
        )
        self._records[doc_id] = record
        self._known_hashes[sha256] = doc_id

        logger.info("Document registered: %s (%s)", filename, doc_id)
        result = ProvenanceResult(
            is_valid=True,
            doc_id=doc_id,
            reason="Document passed all provenance checks",
            record=record,
        )
        self._audit_log.append(result.to_log_entry())
        return result

    def get_record(self, doc_id: str) -> DocumentRecord | None:
        return self._records.get(doc_id)

    def get_audit_log(self) -> List[dict]:
        return list(self._audit_log)
