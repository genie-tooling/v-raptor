# run_web.py
import multiprocessing
import logging
from src.server import app, periodic_sync

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting V-Raptor web server...")
    
    sync_process = multiprocessing.Process(target=periodic_sync)
    sync_process.daemon = True
    sync_process.start()
    logging.info("Started background process for scan status synchronization.")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
