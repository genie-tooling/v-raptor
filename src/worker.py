from redis import Redis
from src.orchestrator import Orchestrator
from src.vcs import VCSService
from src.database import get_session, Repository, Scan
from rq import Queue, Connection, Worker
import os
from src import di
from datetime import datetime, timezone
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


listen = ['default']
redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_conn = Redis(host=redis_host, port=6379)
q = Queue(connection=redis_conn)

def _get_orchestrator():
    """Helper function to create an orchestrator instance."""
    try:
        from googlesearch import search as google_search_tool

        def google_web_search_adapter(query: str) -> str:
            logging.info(f"Performing web search for: '{query}'")
            try:
                results_iterator = google_search_tool(query, num_results=5)
                return "\n".join(list(results_iterator))
            except Exception as e:
                logging.error(f"Web search failed: {e}")
                return ""
        
        di.google_web_search = google_web_search_adapter
        logging.info("Successfully configured the googlesearch-python tool for the worker.")
    except ImportError:
        logging.warning("googlesearch tool not found in worker environment.")
        def placeholder_search(query: str = ""): return ""
        di.google_web_search = placeholder_search
    
    try:
        logging.info("Initializing database session...")
        session = get_session()()
        logging.info("Database session initialized successfully.")

        logging.info("Initializing VCS service...")
        vcs_service = VCSService(git_provider='github', token='')
        logging.info("VCS service initialized successfully.")

        logging.info("Initializing Orchestrator (which includes LLMService)...")
        orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
        logging.info("Orchestrator initialized successfully.")
        
        return orchestrator

    except Exception as e:
        # This will catch any failure during the init steps and log it.
        logging.error(f"Failed to initialize orchestrator components: {e}", exc_info=True)
        return None


def run_deep_scan_job(repo_url, scan_id, auto_patch=False, include_tests=False):
    """
    This is the background task that will be executed by the RQ worker.
    It runs a deep scan on a repository.
    """
    logging.info(f"Starting deep scan job for repo: {repo_url}")
    orchestrator = None
    try:
        orchestrator = _get_orchestrator()
        # Add a check to ensure the orchestrator was created
        if not orchestrator:
            raise RuntimeError("Orchestrator could not be initialized. Check environment and configuration.")
        
        orchestrator.run_deep_scan(repo_url, scan_id, auto_patch=auto_patch, include_tests=include_tests)
        logging.info(f"Deep scan job completed for repo: {repo_url}")
    except Exception as e:
        logging.error(f"Deep scan job failed for repo {repo_url}: {e}", exc_info=True)
    finally:
        if orchestrator and orchestrator.db_session:
            orchestrator.db_session.close()

def run_quality_scan_job(repo_id):
    """
    This is the background task that will be executed by the RQ worker.
    It runs a quality scan on a repository.
    """
    logging.info(f"Starting quality scan job for repo: {repo_id}")
    orchestrator = None
    try:
        orchestrator = _get_orchestrator()
        if not orchestrator:
            raise RuntimeError("Orchestrator could not be initialized. Check environment and configuration.")
        
        orchestrator.run_quality_scan_for_repo(repo_id)
        logging.info(f"Quality scan job completed for repo: {repo_id}")
    except Exception as e:
        logging.error(f"Quality scan job failed for repo {repo_id}: {e}", exc_info=True)
    finally:
        if orchestrator and orchestrator.db_session:
            orchestrator.db_session.close()

def link_cves_to_findings_job(repo_id, scan_id):
    """Job to link CVEs to findings for a repository."""
    session = get_session()()
    orchestrator = Orchestrator(VCSService(git_provider='github', token=''), session, di.google_web_search)
    orchestrator.link_cves_to_findings(repo_id, scan_id)
    session.close()

def run_analysis_job(repo_url, commit_hash, repo_id, auto_patch=False):
    """
    This is the background task that will be executed by the RQ worker.
    It runs a commit analysis.
    """
    logging.info(f"Starting analysis job for repo: {repo_url}, commit: {commit_hash}")
    orchestrator = None
    try:
        orchestrator = _get_orchestrator()
        # Add a check to ensure the orchestrator was created
        if not orchestrator:
            raise RuntimeError("Orchestrator could not be initialized. Check environment and configuration.")

        orchestrator.run_analysis_on_commit(repo_url, commit_hash, repo_id, auto_patch=auto_patch, wait_for_completion=True)
        logging.info(f"Analysis job completed for commit: {commit_hash}")
    except Exception as e:
        logging.error(f"Analysis job failed for commit {commit_hash}: {e}", exc_info=True)
    finally:
        if orchestrator and orchestrator.db_session:
            orchestrator.db_session.close()

def check_for_new_commits_job():
    """
    This is a background task that checks for new commits in all repositories
    and triggers periodic scans.
    """
    logging.info("Starting new commit check job...")
    orchestrator = None
    try:
        orchestrator = _get_orchestrator()
        if not orchestrator:
            raise RuntimeError("Orchestrator could not be initialized. Check environment and configuration.")
        
        repositories = orchestrator.db_session.query(Repository).all()
        for repo in repositories:
            # Check for new commits
            latest_hash = orchestrator.vcs_service.get_latest_commit_hash(repo.url, repo.primary_branch)
            if latest_hash and latest_hash != repo.last_commit_hash:
                logging.info(f"New commits found for {repo.name}. Old hash: {repo.last_commit_hash}, New hash: {latest_hash}")
                repo.last_commit_hash = latest_hash
                repo.needs_scan = True
                orchestrator.db_session.commit()

            # Check for periodic scans
            if repo.periodic_scan_enabled:
                last_scan = orchestrator.db_session.query(Scan).filter_by(repository_id=repo.id, scan_type='deep').order_by(Scan.created_at.desc()).first()
                if not last_scan or (datetime.now(timezone.utc) - last_scan.created_at).total_seconds() > repo.periodic_scan_interval:
                    logging.info(f"Triggering periodic deep scan for {repo.name}")
                    q.enqueue(run_deep_scan_job, repo.url, auto_patch=False)

        logging.info("New commit check job completed.")
    except Exception as e:
        logging.error(f"New commit check job failed: {e}", exc_info=True)
    finally:
        if orchestrator and orchestrator.db_session:
            orchestrator.db_session.close()

def start_worker():
    """Starts the RQ worker."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    try:
        with Connection(redis_conn):
            worker = Worker(map(Queue, listen))
            logging.info(f"RQ Worker started. Listening on queues: {', '.join(listen)}")
            worker.work()
    except Exception as e:
        logging.error(f"Worker crashed with an exception {e}.", exc_info=True)

if __name__ == '__main__':
    start_worker()