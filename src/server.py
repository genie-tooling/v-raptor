import os
from flask import Flask, render_template, request, redirect, url_for, flash
from .database import get_session, Repository, Scan, Finding, Patch, ChatMessage, QualityMetric
from .orchestrator import Orchestrator
from .vcs import VCSService
from .llm import LLMService
from .config import OLLAMA_MODEL, LLM_PROVIDER, LLAMA_CPP_MODEL_PATH, OLLAMA_URL, GEMINI_MODEL
from . import di

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)

try:
    from google_search import search as google_web_search_tool
    di.google_web_search = google_web_search_tool
    print("Successfully imported the google_web_search tool for the web server.")
except ImportError:
    print("Could not import google_search for the web server. Web search will be disabled.")
    def placeholder_search(query: str = ""): return ""
    di.google_web_search = placeholder_search

@app.route('/save_gemini_api_key', methods=['POST'])
def save_gemini_api_key():
    api_key = request.form['gemini_api_key']
    with open('api_key.txt', 'w') as f:
        f.write(api_key)
    return redirect(url_for('config'))

@app.route('/save_ollama_model', methods=['POST'])
def save_ollama_model():
    ollama_model = request.form['ollama_model']
    with open('src/config.py', 'r') as f:
        lines = f.readlines()
    with open('src/config.py', 'w') as f:
        for line in lines:
            if line.startswith('OLLAMA_MODEL'):
                f.write(f"OLLAMA_MODEL = '{ollama_model}'\n")
            else:
                f.write(line)
    return redirect(url_for('config'))

@app.route('/scan_ollama_models', methods=['POST'])
def scan_ollama_models():
    llm_service = LLMService(llm_provider='ollama')
    models = llm_service.get_ollama_models()
    return render_template('config.html', ollama_models=models, selected_ollama_model=OLLAMA_MODEL)

@app.route('/config')
def config():
    return render_template('config.html', llm_provider=LLM_PROVIDER, llama_cpp_model_path=LLAMA_CPP_MODEL_PATH, ollama_url=OLLAMA_URL, gemini_model=GEMINI_MODEL)

@app.route('/save_llm_settings', methods=['POST'])
def save_llm_settings():
    with open('src/config.py', 'r') as f:
        lines = f.readlines()
    with open('src/config.py', 'w') as f:
        for line in lines:
            if line.startswith('LLM_PROVIDER'):
                f.write(f"LLM_PROVIDER = '{request.form['llm_provider']}'\n")
            elif line.startswith('LLAMA_CPP_MODEL_PATH'):
                f.write(f"LLAMA_CPP_MODEL_PATH = '{request.form['llama_cpp_model_path']}'\n")
            elif line.startswith('OLLAMA_URL'):
                f.write(f"OLLAMA_URL = '{request.form['ollama_url']}'\n")
            elif line.startswith('GEMINI_MODEL'):
                f.write(f"GEMINI_MODEL = '{request.form['gemini_model']}'\n")
            else:
                f.write(line)
    return redirect(url_for('config'))

@app.route('/dashboard')
def dashboard():
    session = get_session()()
    orchestrator = Orchestrator(None, session, di.google_web_search)
    metrics = orchestrator.get_dashboard_metrics()
    return render_template('dashboard.html', metrics=metrics)

@app.route('/')
def index():
    session = get_session()()
    repos = session.query(Repository).all()
    return render_template('index.html', repos=repos)

@app.route('/add_repo', methods=['POST'])
def add_repo():
    repo_url = request.form['repo_url']
    vcs_service = VCSService(git_provider='github', token='')
    base_url, detected_branch = vcs_service.parse_and_validate_repo_url(repo_url)

    if not base_url:
        flash(f"Error: Could not find a valid repository at '{repo_url}'. Please check the URL.", 'error')
        return redirect(url_for('index'))

    branches = vcs_service.get_branches(base_url)
    if not branches:
        flash(f"Error: Found repository '{base_url}' but could not fetch its branches.", 'error')
        return redirect(url_for('index'))

    return render_template('select_branch.html',
                           repo_url=base_url,
                           branches=branches,
                           selected_branch=detected_branch)

@app.route('/confirm_add_repo', methods=['POST'])
def confirm_add_repo():
    repo_url = request.form['repo_url']
    selected_branch = request.form['branch'] 
    session = get_session()()
    
    if session.query(Repository).filter_by(url=repo_url).first():
        flash(f"Repository '{repo_url}' is already being monitored.", 'info')
        return redirect(url_for('index'))

    repo_name = repo_url.split('/')[-1].replace('.git', '')
    new_repo = Repository(
        name=repo_name, 
        url=repo_url, 
        primary_branch=selected_branch
    )
    session.add(new_repo)
    session.commit()
    flash(f"Successfully added repository '{repo_name}' (monitoring branch '{selected_branch}').", 'success')
    return redirect(url_for('index'))


@app.route('/remove_repo/<int:repo_id>', methods=['POST'])
def remove_repo(repo_id):
    session = get_session()()
    repo = session.query(Repository).get(repo_id)
    if repo:
        session.delete(repo)
        session.commit()
    return redirect(url_for('index'))

@app.route('/repository/<int:repo_id>')
def repository(repo_id):
    session = get_session()()
    repo = session.query(Repository).get(repo_id)
    return render_template('repository.html', repo=repo)

@app.route('/repository/<int:repo_id>/quality')
def quality(repo_id):
    session = get_session()()
    repo = session.query(Repository).get(repo_id)
    scan = session.query(Scan).filter_by(repository_id=repo_id, scan_type='quality').order_by(Scan.created_at.desc()).first()
    if scan:
        metrics = session.query(QualityMetric).filter_by(scan_id=scan.id).all()
    else:
        metrics = []
    return render_template('quality.html', repo=repo, metrics=metrics)

@app.route('/run_scan/<int:repo_id>', methods=['POST'])
def run_scan(repo_id):
    session = get_session()()
    repo = session.query(Repository).get(repo_id)
    if repo:
        vcs_service = VCSService(git_provider='github', token='')
        orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
        orchestrator.run_deep_scan(repo.url)
    return redirect(url_for('repository', repo_id=repo_id))

@app.route('/rerun_scan/<int:scan_id>', methods=['POST'])
def rerun_scan(scan_id):
    session = get_session()()
    scan = session.query(Scan).get(scan_id)
    if scan:
        vcs_service = VCSService(git_provider='github', token='')
        orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
        if scan.scan_type == 'commit':
            orchestrator.run_analysis_on_commit(scan.repository.url, scan.triggering_commit_hash, scan.repository.id, wait_for_completion=False)
        elif scan.scan_type in ['dependency', 'configuration', 'source', 'secret', 'quality']:
            orchestrator.run_deep_scan(scan.repository.url)
    return redirect(url_for('repository', repo_id=scan.repository.id))

@app.route('/scan/<int:scan_id>')
def scan(scan_id):
    session = get_session()()
    scan = session.query(Scan).get(scan_id)
    return render_template('scan.html', scan=scan)

@app.route('/finding/<int:finding_id>')
def finding(finding_id):
    session = get_session()()
    finding = session.query(Finding).get(finding_id)
    chat_history = session.query(ChatMessage).filter_by(finding_id=finding_id).order_by(ChatMessage.created_at).all()
    return render_template('finding.html', finding=finding, chat_history=chat_history)

@app.route('/recheck_finding/<int:finding_id>', methods=['POST'])
def recheck_finding(finding_id):
    session = get_session()()
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
    orchestrator.recheck_finding(finding_id)
    return redirect(url_for('finding', finding_id=finding_id))

@app.route('/rewrite_remediation/<int:finding_id>', methods=['POST'])
def rewrite_remediation(finding_id):
    session = get_session()()
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
    orchestrator.rewrite_remediation(finding_id)
    return redirect(url_for('finding', finding_id=finding_id))

@app.route('/update_patch/<int:finding_id>', methods=['POST'])
def update_patch(finding_id):
    patch_diff = request.form['patch_diff']
    session = get_session()()
    patch = session.query(Patch).filter_by(finding_id=finding_id).first()
    if patch:
        patch.generated_patch_diff = patch_diff
        session.commit()
    return redirect(url_for('finding', finding_id=finding_id))

@app.route('/chat/<int:finding_id>', methods=['POST'])
def chat(finding_id):
    message = request.json['message']
    session = get_session()()
    orchestrator = Orchestrator(None, session, di.google_web_search)
    response = orchestrator.chat_with_finding(finding_id, message)
    return {'response': response}

@app.route('/ci/scan', methods=['POST'])
def ci_scan():
    repo_url = request.json['repo_url']
    commit_hash = request.json['commit_hash']
    session = get_session()()
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
    repository = session.query(Repository).filter_by(url=repo_url).first()
    if not repository:
        repository = Repository(name=repo_url.split('/')[-1], url=repo_url)
        session.add(repository)
        session.commit()
    scan = orchestrator.run_analysis_on_commit(repo_url, commit_hash, repository.id, wait_for_completion=True)
    high_severity_findings = session.query(Finding).filter(
        Finding.scan_id == scan.id,
        Finding.severity.in_(['HIGH', 'CRITICAL'])
    ).count()
    if high_severity_findings > 0:
        return {'status': 'failure', 'message': f'Found {high_severity_findings} high or critical severity findings.'}
    else:
        return {'status': 'success', 'message': 'No high or critical severity findings found.'}

if __name__ == '__main__':
    app.run(debug=True)