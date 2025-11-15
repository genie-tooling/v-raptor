from sqlalchemy import func
from .database import Repository, Scan, Finding


class Dashboard:
    def __init__(self, db_session):
        self.db_session = db_session

    def get_findings_by_severity(self):
        """Gets the number of findings for each severity from the most recent scan of each repository."""
        # Subquery to find the latest scan_id for each repository
        latest_scan_ids_subquery = self.db_session.query(
            Scan.repository_id,
            func.max(Scan.id).label('latest_scan_id')
        ).group_by(Scan.repository_id).subquery()

        return self.db_session.query(
            Finding.severity,
            func.count(Finding.id)
        ).join(
            Scan,
            Finding.scan_id == Scan.id
        ).join(
            latest_scan_ids_subquery,
            Scan.repository_id == latest_scan_ids_subquery.c.repository_id
        ).filter(
            Scan.id == latest_scan_ids_subquery.c.latest_scan_id
        ).group_by(Finding.severity).all()

    def get_findings_by_repo(self):
        """Gets the number of findings for each repository from the most recent scan."""
        # Subquery to find the latest scan_id for each repository
        latest_scan_ids_subquery = self.db_session.query(
            Scan.repository_id,
            func.max(Scan.id).label('latest_scan_id')
        ).group_by(Scan.repository_id).subquery()

        return self.db_session.query(
            Repository.name,
            func.count(Finding.id)
        ).join(
            Scan,
            Repository.id == Scan.repository_id
        ).join(
            Finding,
            Finding.scan_id == Scan.id
        ).join(
            latest_scan_ids_subquery,
            Scan.repository_id == latest_scan_ids_subquery.c.repository_id
        ).filter(
            Scan.id == latest_scan_ids_subquery.c.latest_scan_id
        ).group_by(Repository.name).all()

    def get_dashboard_metrics(self):
        """Gets metrics for the dashboard."""
        total_repos = self.db_session.query(Repository).count()
        total_scans = self.db_session.query(Scan).count()
        
        # Subquery to find the latest scan_id for each repository
        latest_scan_ids_subquery = self.db_session.query(
            Scan.repository_id,
            func.max(Scan.id).label('latest_scan_id')
        ).group_by(Scan.repository_id).subquery()

        total_findings = self.db_session.query(
            func.count(Finding.id)
        ).join(
            Scan,
            Finding.scan_id == Scan.id
        ).join(
            latest_scan_ids_subquery,
            Scan.repository_id == latest_scan_ids_subquery.c.repository_id
        ).filter(
            Scan.id == latest_scan_ids_subquery.c.latest_scan_id
        ).scalar()

        return {
            'total_repos': total_repos,
            'total_scans': total_scans,
            'total_findings': total_findings
        }
