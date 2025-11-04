import logging
from rq import Worker, Queue, Connection
from redis import Redis
from src.orchestrator import Orchestrator
from src.vcs import VCSService
from src.database import get_session

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

listen = ['default']
redis_conn = Redis()

def run_analysis_job(repo_url, commit_hash, repo_id):
    """
    The function that will be executed by the RQ worker.
    This function exists to instantiate services for a single job.
    """
    logging.info(f"Worker picking up job for repo: {repo_url}, commit: {commit_hash}")
    Session = get_session()
    session = Session()
    try:
        vcs_service = VCSService(git_provider='github', token='')
        orchestrator = Orchestrator(vcs_service, session)
        orchestrator.run_analysis_on_commit(repo_url, commit_hash, repo_id)
        logging.info(f"Successfully finished job for commit {commit_hash}")
    except Exception as e:
        logging.error(f"Job for commit {commit_hash} failed: {e}", exc_info=True)
    finally:
        session.close()


def run_worker():
    """Starts the RQ worker."""
    with Connection(redis_conn):
        worker = Worker(map(Queue, listen))
        logging.info(f"RQ Worker started. Listening on queues: {', '.join(listen)}")
        worker.work()

if __name__ == '__main__':
    run_worker()