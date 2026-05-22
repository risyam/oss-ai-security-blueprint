class DataMinimizer:
    def summarize(self, record: dict, allowed_fields: list[str]) -> str:
        if not record:
            return "No record found."
        visible = {k: v for k, v in record.items() if k in set(allowed_fields)}
        if not visible:
            return "No fields available for this role."
        pairs = [f"{key}: {value}" for key, value in visible.items()]
        return "; ".join(pairs)
