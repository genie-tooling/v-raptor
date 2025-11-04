import argparse
import logging
from src.orchestrator import Orchestrator
from src.vcs import VCSService
from src.database import init_db

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def main():
    parser = argparse.ArgumentParser(description="V-Raptor: AI-Powered Code Analysis")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Sub-parser for initializing the database
    subparsers.add_parser('init-db', help='Initialize the database schema.')

    # Sub-parser for running a single, synchronous scan
    scan_parser = subparsers.add_parser('scan-commit', help='Run a one-time scan on a specific commit.')
    scan_parser.add_argument('--repo-url', required=True, help='The URL of the git repository.')
    scan_parser.add_argument('--commit-hash', required=True, help='The commit hash to analyze.')
    scan_parser.add_argument('--repo-id', required=True, type=int, help='The ID of the repository in the database.')

    # Sub-parser for running a deep scan
    deep_scan_parser = subparsers.add_parser('deep-scan', help='Run a deep scan on a repository.')
    deep_scan_parser.add_argument('--repo-url', required=True, help='The URL of the git repository.')

    # Sub-parser for starting the webhook server
    subparsers.add_parser('start-server', help='Start the webhook server to listen for git events.')

    # Sub-parser for starting the task worker
    subparsers.add_parser('start-worker', help='Start an RQ worker to process analysis jobs.')

    # Sub-parser for generating a report
    subparsers.add_parser('generate-report', help='Generate an HTML report of findings.')

    args = parser.parse_args()

    if args.command == 'init-db':
        print("Initializing database...")
        init_db()
        print("Database initialized.")
    elif args.command == 'scan-commit':
        from src.database import get_session
        Session = get_session()
        session = Session()
        try:
            vcs_service = VCSService(git_provider='github', token='')
            orchestrator = Orchestrator(vcs_service, session)
            orchestrator.run_analysis_on_commit(repo_url=args.repo_url, commit_hash=args.commit_hash, repo_id=args.repo_id)
        finally:
            session.close()
    elif args.command == 'deep-scan':
        from src.database import get_session
        Session = get_session()
        session = Session()
        try:
            vcs_service = VCSService(git_provider='github', token='')
            orchestrator = Orchestrator(vcs_service, session)
            orchestrator.run_deep_scan(repo_url=args.repo_url)
        finally:
            session.close()
    elif args.command == 'start-server':
        # Import here to avoid circular dependencies and keep CLI fast
        from src.webhook_server import app
        # In a production environment, use Gunicorn
        # gunicorn --workers 4 --bind 0.0.0.0:5000 webhook_server:app
        print("Starting Flask server for webhooks. Use Gunicorn in production.")
        app.run(port=5000, host='0.0.0.0')
    elif args.command == 'start-worker':
        # Import here for the same reasons as above
        from src.worker import run_worker
        run_worker()
    elif args.command == 'generate-report':
        from src.report import generate_report
        generate_report()

if __name__ == '__main__':
    main()