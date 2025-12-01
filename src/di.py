from .vcs import VCSService
from .orchestrator import Orchestrator
from .database import get_session

google_web_search = None

def get_vcs_service():
    return VCSService(git_provider='github', token='')

def get_orchestrator():
    session = get_session()()
    vcs_service = get_vcs_service()
    return Orchestrator(vcs_service, session, google_web_search)

def get_worker_orchestrator():
    """Helper function to create an orchestrator instance for the worker."""
    try:
        from googlesearch import search as google_search_tool

        def google_web_search_adapter(query: str) -> str:
            import logging
            logging.info(f"Performing web search for: '{query}'")
            try:
                results_iterator = google_search_tool(query, num_results=5)
                return "\n".join(list(results_iterator))
            except Exception as e:
                logging.error(f"Web search failed: {e}")
                return ""
        
        google_web_search = google_web_search_adapter
    except ImportError:
        def placeholder_search(query: str = ""): return ""
        google_web_search = placeholder_search
    
    session = get_session()()
    vcs_service = get_vcs_service()
    return Orchestrator(vcs_service, session, google_web_search)