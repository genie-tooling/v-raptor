# src/scheduler.py

import time
import logging
from rq import Queue
from redis import Redis
from src.worker import check_for_new_commits_job

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def main():
    """
    This is the scheduler process. It periodically enqueues the
    check_for_new_commits_job.
    """
    redis_host = 'localhost'
    redis_conn = Redis(host=redis_host, port=6379)
    q = Queue(connection=redis_conn)
    
    # Schedule the job to run every 5 minutes
    schedule_interval = 300 # seconds

    logging.info("Scheduler started.")
    while True:
        logging.info("Enqueuing new commit check job...")
        q.enqueue(check_for_new_commits_job)
        logging.info(f"Sleeping for {schedule_interval} seconds...")
        time.sleep(schedule_interval)

if __name__ == '__main__':
    main()
