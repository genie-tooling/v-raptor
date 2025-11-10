# src/worker.py

import logging
import os
from rq import Worker, Queue, Connection
from redis import Redis
from src.orchestrator import Orchestrator
from src.vcs import VCSService
from src.database import get_session
from src import di

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


listen = ['default']
redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_conn = Redis(host=redis_host, port=6379)

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


def run_deep_scan_job(repo_url, auto_patch=False):
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
        
        orchestrator.run_deep_scan(repo_url, auto_patch=auto_patch)
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

def link_cves_to_findings_job(repo_id):
    """
    This is the background task that will be executed by the RQ worker.
    It runs a CVE scan on a repository.
    """
    logging.info(f"Starting CVE linking job for repo: {repo_id}")
    orchestrator = None
    try:
        orchestrator = _get_orchestrator()
        if not orchestrator:
            raise RuntimeError("Orchestrator could not be initialized. Check environment and configuration.")
        
        orchestrator.link_cves_to_findings(repo_id)
        logging.info(f"CVE linking job completed for repo: {repo_id}")
    except Exception as e:
        logging.error(f"CVE linking job failed for repo {repo_id}: {e}", exc_info=True)
    finally:
        if orchestrator and orchestrator.db_session:
            orchestrator.db_session.close()

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

def start_worker():
    """Starts the RQ worker."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    try:
        with Connection(redis_conn):
            worker = Worker(map(Queue, listen))
            logging.info(f"RQ Worker started. Listening on queues: {', '.join(listen)}")
            worker.work()
    except Exception as e:
        logging.error("Worker crashed with an exception.", exc_info=True)

if __name__ == '__main__':
    start_worker()