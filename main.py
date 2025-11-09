import argparse
from src.database import get_session, init_db, Repository
from src.orchestrator import Orchestrator
from src.vcs import VCSService
from src.worker import start_worker
from src import di

def main():
    parser = argparse.ArgumentParser(description='V-Raptor')
    parser.add_argument('--scan-url', help='The URL of the repository to scan.')
    parser.add_argument('--scan-commit', help='The commit hash to scan.')
    parser.add_argument('--start-worker', action='store_true', help='Starts a worker process.')
    parser.add_argument('--start-web', action='store_true', help='Starts the web server.')
    parser.add_argument('--init-db', action='store_true', help='Initializes the database.')

    args = parser.parse_args()

    if args.init_db:
        init_db()
        print("Database initialized.")
        return

    try:
        from googlesearch import search as google_search_tool

        def google_web_search_adapter(query: str) -> str:
            """
            Performs a search and returns the top 5 results as a newline-separated string.
            """
            print(f"Performing web search for: '{query}'")
            try:
                # The search tool returns a generator, so we collect a few results
                results_iterator = google_search_tool(query, num_results=5)
                return "\n".join(list(results_iterator))
            except Exception as e:
                print(f"Web search failed: {e}")
                return ""

        di.google_web_search = google_web_search_adapter
        print("Successfully imported and configured the googlesearch-python tool.")
    except ImportError:
        print("Could not import the googlesearch tool. Web search validation will be disabled.")
        def placeholder_search(query: str = "") -> str:
            print("Warning: Web search is not available in this environment. Returning no results.")
            return ""
        di.google_web_search = placeholder_search

    if args.start_worker:
        start_worker()
        return

    if args.start_web:
        from src.server import app
        app.run(debug=True)
        return

    if not args.scan_url:
        print("Please provide a repository URL to scan with --scan-url.")
        return

    session = get_session()()
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session, di.google_web_search)

    repo = session.query(Repository).filter_by(url=args.scan_url).first()
    if not repo:
        print(f"Repository {args.scan_url} not found in database. Adding it.")
        repo_name = args.scan_url.split('/')[-1].replace('.git', '')
        repo = Repository(name=repo_name, url=args.scan_url)
        session.add(repo)
        session.commit()

    if args.scan_commit:
        print(f"--- Starting commit scan for {args.scan_url} at commit {args.scan_commit} ---")
        orchestrator.run_analysis_on_commit(args.scan_url, args.scan_commit, repo.id, wait_for_completion=True)
    else:
        print(f"--- Starting deep scan for {args.scan_url} ---")
        orchestrator.run_deep_scan(args.scan_url)

    print("--- Scan complete. ---")
    # -------------------------------------------------------------
if __name__ == '__main__':
    main()