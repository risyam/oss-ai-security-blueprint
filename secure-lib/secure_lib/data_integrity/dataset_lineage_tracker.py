import uuid
from dataclasses import dataclass


@dataclass
class LineageRecord:
    sample_id: str
    source_id: str
    uploader: str
    approval_state: str
    transforms: list[str]


class DatasetLineageTracker:
    def __init__(self):
        self._records: dict[str, LineageRecord] = {}

    def register(self, source_id: str, uploader: str, approval_state: str, transforms: list[str] | None = None) -> LineageRecord:
        record = LineageRecord(
            sample_id=str(uuid.uuid4()),
            source_id=source_id,
            uploader=uploader,
            approval_state=approval_state,
            transforms=transforms or [],
        )
        self._records[record.sample_id] = record
        return record

    def get(self, sample_id: str) -> LineageRecord | None:
        return self._records.get(sample_id)
