from copy import deepcopy


CLASSIFICATION_POLICY = {
    "employee": {"public"},
    "hr_operator": {"public", "internal"},
    "admin": {"public", "internal", "restricted"},
}


class FieldAccessPolicy:
    def __init__(self, field_classification: dict[str, str] | None = None):
        self.field_classification = field_classification or {}

    def filter_record(self, record: dict, role: str) -> dict:
        allowed_classes = CLASSIFICATION_POLICY.get((role or "").lower(), {"public"})
        filtered = {}
        for key, value in deepcopy(record).items():
            classification = self.field_classification.get(key, "public")
            if classification in allowed_classes:
                filtered[key] = value
        return filtered
