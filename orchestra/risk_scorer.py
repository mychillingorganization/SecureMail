def final_status_from_issue_count(issue_count: int) -> str:
    """Map issue counter to final status."""
    if issue_count <= 0:
        return "PASS"
    if issue_count == 1:
        return "WARNING"
    return "DANGER"
