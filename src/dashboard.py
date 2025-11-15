from sqlalchemy import func
from .database import Repository, Scan, Finding


class Dashboard:
    def __init__(self, db_session):
        self.db_session = db_session

    def get_findings_by_severity(self):
        """Gets the number of findings for each severity."""
        return self.db_session.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all()

    def get_findings_by_repo(self):
        """Gets the number of findings for each repository."""
        return self.db_session.query(Repository.name, func.count(Finding.id)).select_from(Repository).join(Scan).join(Finding).group_by(Repository.name).all()

    def get_dashboard_metrics(self):
        """Gets metrics for the dashboard."""
        total_repos = self.db_session.query(Repository).count()
        total_scans = self.db_session.query(Scan).count()
        total_findings = self.db_session.query(Finding).count()

        return {
            'total_repos': total_repos,
            'total_scans': total_scans,
            'total_findings': total_findings
        }
