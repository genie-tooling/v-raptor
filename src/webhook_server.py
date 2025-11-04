import logging
from flask import Flask, request, jsonify
from rq import Queue
from redis import Redis
from src.database import get_session, Repository
from worker import run_analysis_job

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Set up Redis connection and RQ Queue
redis_conn = Redis()
q = Queue(connection=redis_conn)

@app.route('/webhook', methods=['POST'])
def webhook():
    """Endpoint to receive GitHub push webhooks."""
    data = request.json
    
    # Simple validation for GitHub push events
    if request.headers.get('X-GitHub-Event') != 'push':
        return jsonify({'status': 'ignored', 'reason': 'not a push event'}), 200

    try:
        repo_url = data['repository']['clone_url']
        commit_hash = data['after'] # The latest commit hash on the pushed branch
        repo_full_name = data['repository']['full_name']

        # Don't process commits from a deleted branch
        if commit_hash == '0000000000000000000000000000000000000000':
            return jsonify({'status': 'ignored', 'reason': 'branch deleted'}), 200

        logging.info(f"Received push event for repo: {repo_full_name}, commit: {commit_hash[:7]}")

        Session = get_session()
        session = Session()
        try:
            # Check if we are tracking this repository
            repo = session.query(Repository).filter_by(url=repo_url).first()
            if not repo:
                # If not, let's add it
                logging.info(f"First time seeing repo '{repo_full_name}'. Adding to database.")
                repo = Repository(name=repo_full_name, url=repo_url)
                session.add(repo)
                session.commit()
            
            # Enqueue the analysis job
            job = q.enqueue(
                run_analysis_job,
                repo_url,
                commit_hash,
                repo.id,
                job_timeout='10m' # Job can run for up to 10 minutes
            )
            logging.info(f"Enqueued job {job.id} for commit {commit_hash[:7]}")
            
        finally:
            session.close()

        return jsonify({'status': 'enqueued', 'job_id': job.id}), 202

    except KeyError as e:
        logging.error(f"Webhook payload missing expected key: {e}")
        return jsonify({'error': 'invalid payload'}), 400
    except Exception as e:
        logging.error(f"An error occurred while processing webhook: {e}")
        return jsonify({'error': 'internal server error'}), 500


if __name__ == '__main__':
    app.run(port=5000, host='0.0.0.0', debug=True)