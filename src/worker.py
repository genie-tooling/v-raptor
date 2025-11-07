# src/worker.py

import logging
from rq import Worker, Queue, Connection
from redis import Redis
from src.orchestrator import Orchestrator
from src.vcs import VCSService
from src.database import get_session
from src import di

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

listen = ['default']
redis_conn = Redis()

def run_analysis_job(repo_url, commit_hash, repo_id):
    """
    This is the background task that will be executed by the RQ worker.
    It runs a commit analysis.
    """
    logging.info(f"Starting analysis job for repo: {repo_url}, commit: {commit_hash}")
    try:
        from google_search import search as google_web_search_tool
        di.google_web_search = google_web_search_tool
    except ImportError:
        logging.warning("google_search tool not found in worker environment.")
        def placeholder_search(query: str = ""): return ""
        di.google_web_search = placeholder_search
    # ----------------------------------------------------

    session = get_session()()
    try:
        vcs_service = VCSService(git_provider='github', token='')
        orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
        orchestrator.run_analysis_on_commit(repo_url, commit_hash, repo_id, wait_for_completion=True)
        logging.info(f"Analysis job completed for commit: {commit_hash}")
    except Exception as e:
        logging.error(f"Analysis job failed for commit {commit_hash}: {e}", exc_info=True)
    finally:
        session.close()

def start_worker():
    """Starts the RQ worker."""
    with Connection(redis_conn):
        worker = Worker(map(Queue, listen))
        logging.info(f"RQ Worker started. Listening on queues: {', '.join(listen)}")
        worker.work()

if __name__ == '__main__':
    start_worker()