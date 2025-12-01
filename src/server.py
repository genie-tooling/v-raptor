import os
import re
from sqlalchemy import func, case
from sqlalchemy.orm import selectinload
from flask import g, Flask, render_template, request, redirect, url_for, flash, jsonify
from redis import Redis
from rq import Queue
from rq.registry import FailedJobRegistry
from .database import get_session, Repository, Scan, Finding, Patch, ChatMessage, QualityMetric, QualityInterpretation, ScanStatus
from rq.job import Job
from .orchestrator import Orchestrator
from .vcs import VCSService
from .llm import LLMService
from .sandbox import SandboxService
from . import config
from . import di
from collections import defaultdict

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)

redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_conn = Redis(host=redis_host, port=6379)
q = Queue(connection=redis_conn, default_timeout=3600)

try:
    from googlesearch import search as google_search_tool

    def google_web_search_adapter(query: str) -> str:
        """
        Performs a search and returns the top 5 results as a newline-separated string.
        """
        print(f"Performing web search for: '{query}'")
        try:
            results_iterator = google_search_tool(query, num_results=5)
            return "\n".join(list(results_iterator))
        except Exception as e:
            print(f"Web search failed: {e}")
            return ""

    di.google_web_search = google_web_search_adapter
    print("Successfully imported and configured the googlesearch-python tool for the web server.")
except ImportError:
    print("Could not import googlesearch for the web server. Web search will be disabled.")
    def placeholder_search(query: str = ""):
        return ""
    di.google_web_search = placeholder_search

@app.route('/config')
def config_page():
    llm_service = LLMService()
    scanner_models = llm_service.get_available_models('scanner')
    patcher_models = llm_service.get_available_models('patcher')
    return render_template('config.html', config=config, scanner_models=scanner_models, patcher_models=patcher_models)

@app.route('/api/probe_image', methods=['POST'])
def probe_image():
    image_name = request.json.get('image_name')
    if not image_name:
        return jsonify({'error': 'Image name is required'}), 400
    
    try:
        sandbox_service = SandboxService()
        detected_entrypoint = sandbox_service.probe_image(image_name)
        
        if detected_entrypoint:
            return jsonify({'status': 'success', 'entrypoint': detected_entrypoint})
        else:
            return jsonify({'status': 'error', 'message': 'Could not detect a compatible shell (/bin/bash or /bin/sh).'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/save_settings', methods=['POST'])
def save_settings():
    config_path = os.path.join(os.path.dirname(__file__), 'config.py')
    
    with open(config_path, 'w') as f:
        f.write("# src/config.py\n\n")
        
        f.write("# --- Scanner Model Configuration ---\\n")
        f.write(f"SCANNER_LLM_PROVIDER = '{request.form.get('scanner_llm_provider')}'\n")
        f.write(f"SCANNER_LLAMA_CPP_MODEL_PATH = r'{request.form.get('scanner_llama_cpp_model_path')}'\n")
        f.write(f"SCANNER_OLLAMA_MODEL = '{request.form.get('scanner_ollama_model')}'\n")
        f.write(f"SCANNER_OLLAMA_URL = '{request.form.get('scanner_ollama_url')}'\n")
        f.write(f"SCANNER_GEMINI_MODEL = '{request.form.get('scanner_gemini_model')}'\n\n")

        f.write("# --- Patcher Model Configuration ---\\n")
        f.write(f"PATCHER_LLM_PROVIDER = '{request.form.get('patcher_llm_provider')}'\n")
        f.write(f"PATCHER_LLAMA_CPP_MODEL_PATH = r'{request.form.get('patcher_llama_cpp_model_path')}'\n")
        f.write(f"PATCHER_OLLAMA_MODEL = '{request.form.get('patcher_ollama_model')}'\n")
        f.write(f"PATCHER_OLLAMA_URL = '{request.form.get('patcher_ollama_url')}'\n")
        f.write(f"PATCHER_GEMINI_MODEL = '{request.form.get('patcher_gemini_model')}'\n\n")
        
        f.write("# --- LLM Timeout ---\\n")
        f.write(f"LLM_TIMEOUT = {request.form.get('llm_timeout')}\n\n")

        f.write("# --- Database Configuration ---\\n")
        f.write(f"DATABASE_URL = '{request.form.get('database_url')}'\n\n")

        f.write("# --- Tool Paths ---\\n")
        f.write(f"GITLEAKS_PATH = '{request.form.get('gitleaks_path')}'\n")
        f.write(f"SEMGREP_PATH = '{request.form.get('semgrep_path')}'\n")
        f.write(f"BANDIT_PATH = '{request.form.get('bandit_path')}'\n\n")

        f.write("# --- SAST Global Exclusions ---\\n")
        exclusions = [item.strip() for item in request.form.get('sast_global_exclusions').split(',')]
        f.write(f"SAST_GLOBAL_EXCLUSIONS = {exclusions}\n")
        f.write(f"DOCKER_REGISTRY = '{request.form.get('docker_registry')}'\n")
        f.write(f"GENERATE_TEST_SCRIPT_DEFAULT = {request.form.get('generate_test_script_default', 'False')}\n")
        f.write(f"RUN_TESTS_IN_CONTAINER_DEFAULT = {'run_tests_in_container_default' in request.form}\n")

        # Handle Test Containers (List of Dicts)
        image_names = request.form.getlist('container_image[]')
        entrypoints = request.form.getlist('container_entrypoint[]')
        
        test_containers = []
        for i in range(len(image_names)):
            if image_names[i].strip():
                test_containers.append({
                    'image': image_names[i].strip(),
                    'entrypoint': entrypoints[i].strip()
                })
        
        f.write(f"TEST_CONTAINER_IMAGES = {test_containers}\n")

    if 'gemini_api_key' in request.form and request.form['gemini_api_key']:
        with open('api_key.txt', 'w') as f:
            f.write(request.form['gemini_api_key'])

    flash("Settings saved successfully. You may need to restart the application for all changes to take effect.", 'success')
    return redirect(url_for('config_page'))

@app.route('/failed_jobs')
def failed_jobs():
    registry = FailedJobRegistry(queue=q)
    failed_jobs = []
    for job_id in registry.get_job_ids():
        job = q.fetch_job(job_id)
        if job:
            failed_jobs.append({
                'id': job.id,
                'func_name': job.func_name,
                'args': job.args,
                'kwargs': job.kwargs,
                'exc_info': job.exc_info
            })
    return render_template('failed_jobs.html', failed_jobs=failed_jobs)

@app.route('/findings')
def findings():
    session = g.db_session
    repo_filter = request.args.get('repository_id')
    severity_filter = request.args.get('severity')
    scanner_filter = request.args.get('scanner')

    repos = session.query(Repository).all()
    findings_query = session.query(Finding)

    if repo_filter:
        findings_query = findings_query.join(Scan).filter(Scan.repository_id == repo_filter)
    if severity_filter:
        findings_query = findings_query.filter(Finding.severity == severity_filter)
    if scanner_filter:
        findings_query = findings_query.filter(Finding.description.like(f"{scanner_filter}:%"))

    findings = findings_query.order_by(Finding.id.desc()).all()
    
    return render_template('findings_page.html', findings=findings, repos=repos,
                           repo_filter=repo_filter, severity_filter=severity_filter,
                           scanner_filter=scanner_filter)

@app.route('/reports')
def reports():
    session = g.db_session
    
    # Subquery to find the latest scan_id for each repository
    latest_scan_ids_subquery = session.query(
        Scan.repository_id,
        func.max(Scan.id).label('latest_scan_id')
    ).group_by(Scan.repository_id).subquery()

    top_vulnerabilities = session.query(
        Finding.description,
        func.count(Finding.id).label('count')
    ).join(
        Scan,
        Finding.scan_id == Scan.id
    ).join(
        latest_scan_ids_subquery,
        Scan.repository_id == latest_scan_ids_subquery.c.repository_id
    ).filter(
        Scan.id == latest_scan_ids_subquery.c.latest_scan_id
    ).group_by(Finding.description).order_by(func.count(Finding.id).desc()).limit(5).all()

    top_repos = session.query(
        Repository.id,
        Repository.name,
        func.count(Finding.id).label('count')
    ).join(
        Scan,
        Repository.id == Scan.repository_id
    ).join(
        Finding,
        Finding.scan_id == Scan.id
    ).join(
        latest_scan_ids_subquery,
        Scan.repository_id == latest_scan_ids_subquery.c.repository_id
    ).filter(
        Scan.id == latest_scan_ids_subquery.c.latest_scan_id
    ).group_by(Repository.id, Repository.name).order_by(func.count(Finding.id).desc()).limit(5).all()

    # Query for vulnerabilities per LOC
    latest_scan = session.query(
        Scan.repository_id,
        func.max(Scan.id).label('max_scan_id')
    ).group_by(Scan.repository_id).subquery()

    vulnerabilities_per_loc = session.query(
        Repository.name,
        func.sum(QualityMetric.sloc).label('total_sloc'),
        func.count(Finding.id).label('total_vulnerabilities'),
        func.sum(case((Finding.severity == 'HIGH', 1), else_=0)).label('high_vulnerabilities'),
        func.sum(case((Finding.severity == 'MEDIUM', 1), else_=0)).label('medium_vulnerabilities'),
        func.sum(case((Finding.severity == 'LOW', 1), else_=0)).label('low_vulnerabilities')
    ).join(latest_scan, Repository.id == latest_scan.c.repository_id
    ).join(Scan, Scan.id == latest_scan.c.max_scan_id
    ).outerjoin(Finding, Finding.scan_id == Scan.id
    ).outerjoin(QualityMetric, QualityMetric.scan_id == Scan.id
    ).group_by(Repository.name).all()

    return render_template('reports.html', top_vulnerabilities=top_vulnerabilities, top_repos=top_repos, vulnerabilities_per_loc=vulnerabilities_per_loc)


@app.route('/failed_jobs/<job_id>')
def failed_job(job_id):
    job = q.fetch_job(job_id)
    return render_template('failed_job.html', job=job)

@app.route('/dashboard')
def dashboard():
    session = g.db_session
    repo_id = request.args.get('repo_id')
    orchestrator = Orchestrator(None, session, di.google_web_search)
    metrics = orchestrator.get_dashboard_metrics()
    recent_scans = session.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()
    
    findings_by_severity_query = orchestrator.get_findings_by_severity()
    if repo_id:
        findings_by_severity_query = findings_by_severity_query.join(Scan).filter(Scan.repository_id == repo_id)
    findings_by_severity = findings_by_severity_query.all()

    findings_by_repo = orchestrator.get_findings_by_repo()
    findings_by_repo_json = [[repo, count] for repo, count in findings_by_repo]
    
    avg_quality_metrics = orchestrator.dashboard.get_average_quality_metrics_by_repo()
    quality_metrics_json = {
        'labels': [row.name for row in avg_quality_metrics],
        'avg_maintainability': [round(row.avg_maintainability or 0, 2) for row in avg_quality_metrics],
        'code_coverage': [round(row.code_coverage or 0, 2) for row in avg_quality_metrics]
    }
    
    repos = session.query(Repository).all()

    languages_by_repo = orchestrator.dashboard.get_languages_by_repo()
    findings_by_lang_across_repos = orchestrator.dashboard.get_findings_by_language_across_repos()
    findings_by_lang_per_repo = orchestrator.dashboard.get_findings_by_language_per_repo()

    return render_template(
        'dashboard.html', 
        metrics=metrics, 
        recent_scans=recent_scans, 
        findings_by_severity=findings_by_severity, 
        findings_by_repo=findings_by_repo_json,
        quality_metrics=quality_metrics_json,
        repos=repos,
        languages_by_repo=languages_by_repo,
        findings_by_lang_across_repos=findings_by_lang_across_repos,
        findings_by_lang_per_repo=findings_by_lang_per_repo
    )

@app.route('/')
def index():
    session = g.db_session
    repos = session.query(Repository).all()
    return render_template('index.html', repos=repos)

@app.route('/add_repo', methods=['POST'])
def add_repo():
    repo_url = request.form['repo_url']
    vcs_service = di.get_vcs_service()
    base_url, _ = vcs_service.parse_and_validate_repo_url(repo_url)
    if not base_url:
        flash(f"Error: Could not find a valid repository at '{repo_url}'. Please check the URL.", 'error')
        return redirect(url_for('index'))

    session = g.db_session
    if session.query(Repository).filter_by(url=base_url).first():
        flash(f"Repository '{base_url}' is already being monitored.", 'info')
        return redirect(url_for('index'))

    repo_name = base_url.split('/')[-1].replace('.git', '')
    new_repo = Repository(name=repo_name, url=base_url, primary_branch=None)
    session.add(new_repo)
    session.commit()

    # Setup new repository
    orchestrator = di.get_orchestrator()
    orchestrator.setup_new_repository(new_repo)
    
    flash(f"Successfully added repository '{repo_name}'.", 'success')
    return redirect(url_for('repository', repo_id=new_repo.id))

@app.route('/repository/<int:repo_id>/periodic_scan', methods=['POST'])
def periodic_scan_config(repo_id):
    session = g.db_session
    repo = session.get(Repository, repo_id)
    if repo:
        repo.periodic_scan_enabled = 'periodic_scan_enabled' in request.form
        repo.periodic_scan_interval = int(request.form.get('periodic_scan_interval', 86400))
        session.commit()
        flash("Periodic scan settings updated.", 'success')
    return redirect(url_for('repository', repo_id=repo_id))

@app.route('/repository/<int:repo_id>/test_command', methods=['POST'])
def save_test_command(repo_id):
    session = g.db_session
    repo = session.get(Repository, repo_id)
    if repo:
        test_command = request.form.get('test_command', '').strip().replace('\r\n', '\n')
        repo.test_command = test_command
        repo.use_venv = 'use_venv' in request.form
        repo.python_version = request.form.get('python_version')
        repo.test_container = request.form.get('test_container')
        
        # Handle tri-state (Default/True/False) logic for execution environment
        exec_env = request.form.get('run_tests_in_container')
        if exec_env == 'true':
            repo.run_tests_in_container = True
        elif exec_env == 'false':
            repo.run_tests_in_container = False
        else:
            # Default or 'default'
            repo.run_tests_in_container = None

        session.commit()
        flash("Test command updated successfully.", 'success')
    return redirect(url_for('repository', repo_id=repo_id))

@app.route('/repository/<int:repo_id>/generate_test_command', methods=['POST'])
def generate_test_command(repo_id):
    session = g.db_session
    repo = session.get(Repository, repo_id)
    if repo:
        vcs_service = VCSService(git_provider='github', token='')
        orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
        
        # Get instructions from JSON payload
        data = request.get_json() or {}
        instructions = data.get('instructions')
        
        test_command = orchestrator.generate_test_command(repo, instructions)
        if test_command:
            repo.test_command = test_command
            session.commit()
            return jsonify({'test_command': test_command})
        else:
            return jsonify({'error': 'Could not generate test command.'}), 500
    return jsonify({'error': 'Repository not found.'}), 404

@app.route('/remove_repo/<int:repo_id>', methods=['POST'])
def remove_repo(repo_id):
    session = g.db_session
    repo = session.get(Repository, repo_id)
    if repo:
        session.delete(repo)
        session.commit()
        return redirect(url_for('index'))
        
@app.route('/repository/<int:repo_id>')
def repository(repo_id):
    session = g.db_session
    repo = session.query(Repository).options(
        selectinload(Repository.scans)
    ).filter_by(id=repo_id).one_or_none()
    
    if not repo:
        flash(f"Repository with ID {repo_id} not found.", "error")
        return redirect(url_for('index'))
    
    vcs_service = VCSService(git_provider='github', token='')
    branches = vcs_service.get_branches(repo.url)

    scans_as_list = list(repo.scans)
    return render_template('repository.html', repo=repo, scans_as_list=scans_as_list, branches=branches, config=config)

@app.route('/repository/<int:repo_id>/sast_exclusions', methods=['POST'])
def save_sast_exclusions(repo_id):
    session = g.db_session
    repo = session.get(Repository, repo_id)
    if repo:
        repo.sast_exclusions = request.form.get('sast_exclusions')
        session.commit()
        flash("SAST exclusions updated successfully.", 'success')
    return redirect(url_for('repository', repo_id=repo_id))


@app.route('/repository/<int:repo_id>/quality')
def quality(repo_id):
    session = g.db_session
    repo = session.get(Repository, repo_id)
    scan = session.query(Scan).filter_by(repository_id=repo_id, scan_type='quality').order_by(Scan.created_at.desc()).first()
    
    sort_by = request.args.get('sort_by', 'file_path')
    sort_order = request.args.get('sort_order', 'asc')

    if scan:
        metrics_query = session.query(QualityMetric).filter_by(scan_id=scan.id)
        
        sort_column = getattr(QualityMetric, sort_by, QualityMetric.file_path)
        if sort_order == 'desc':
            metrics_query = metrics_query.order_by(sort_column.desc())
        else:
            metrics_query = metrics_query.order_by(sort_column.asc())
            
        metrics = metrics_query.all()
    else:
        metrics = []
        
    return render_template('quality.html', repo=repo, metrics=metrics, sort_by=sort_by, sort_order=sort_order)

@app.route('/api/scans')
def api_scans():
    session = g.db_session
    scans = session.query(Scan).order_by(Scan.created_at.desc()).all()
    scans_data = []
    for scan in scans:
        job = q.fetch_job(str(scan.id))
        scans_data.append({
            'id': scan.id,
            'status': scan.status.value,
            'status_message': scan.status_message,
            'job_id': job.id if job else None,
            'progress': scan.progress,
            'total_progress': scan.total_progress,
        })
    return jsonify(scans_data)

@app.route('/scans')
def scans():
    session = g.db_session
    scans = session.query(Scan).order_by(Scan.created_at.desc()).all()
    return render_template('scans.html', scans=scans)

@app.route('/findings/by_description')
def findings_by_description():
    description = request.args.get('description')
    session = g.db_session
    findings = session.query(Finding).filter_by(description=description).all()
    return render_template('findings.html', findings=findings, title=f"Findings for '{description}'")

@app.route('/run_scan/<int:repo_id>', methods=['POST'])
def run_scan(repo_id):
    app.logger.info(f"--- run_scan called for repo_id: {repo_id} ---")
    session = g.db_session
    repo = session.get(Repository, repo_id)
    if repo:
        auto_patch = 'auto_patch' in request.form
        include_tests = 'include_tests' in request.form
        generate_test_script = 'generate_test_script' in request.form
        branch = request.form.get('branch')
        scan = Scan(repository_id=repo.id, scan_type='deep', status='queued', auto_patch_enabled=auto_patch, branch=branch, generate_test_script=generate_test_script)
        session.add(scan)
        session.commit()
        app.logger.info(f"--- Created scan with id: {scan.id} ---")
        job = q.enqueue('src.worker.run_deep_scan_job', repo.url, scan.id, auto_patch=auto_patch, include_tests=include_tests, branch=branch)
        scan.job_id = job.id
        session.commit()
        flash(f"Deep scan initiated for '{repo.name}' on branch '{branch}'.", 'info')
    return redirect(url_for('repository', repo_id=repo_id))

@app.route('/run_test_scan/<int:repo_id>', methods=['POST'])
def run_test_scan(repo_id):
    session = g.db_session
    repo = session.get(Repository, repo_id)
    if repo:
        scan = Scan(repository_id=repo.id, scan_type='test', status='queued')
        session.add(scan)
        session.commit()
        job = q.enqueue('src.worker.run_test_scan_job', repo.id, scan.id)
        scan.job_id = job.id
        session.commit()
        flash(f"Test scan initiated for '{repo.name}'.", 'info')
    return redirect(url_for('repository', repo_id=repo_id))

@app.route('/scan_new_commits/<int:repo_id>', methods=['POST'])
def scan_new_commits(repo_id):
    session = g.db_session
    repo = session.get(Repository, repo_id)
    if repo and repo.needs_scan:
        job = q.enqueue('src.worker.run_analysis_job', repo.url, repo.last_commit_hash, repo.id, auto_patch=False)
        scan = Scan(repository_id=repo.id, scan_type='commit', status='queued', job_id=job.id, triggering_commit_hash=repo.last_commit_hash)
        session.add(scan)
        repo.needs_scan = False
        session.commit()
        flash(f"Scan for new commits initiated for '{repo.name}'.", 'info')
    return redirect(url_for('index'))

@app.route('/run_quality_scan/<int:repo_id>', methods=['POST'])
def run_quality_scan(repo_id):
    session = g.db_session
    repo = session.get(Repository, repo_id)
    if repo:
        # Create the scan object first
        scan = Scan(repository_id=repo.id, scan_type='quality', status='queued')
        session.add(scan)
        session.commit()
        
        # Now enqueue the job with the new scan_id
        job = q.enqueue('src.worker.run_quality_scan_job', scan.id)
        
        # Update the scan object with the job_id
        scan.job_id = job.id
        session.commit()
        
        flash(f"Code quality scan initiated for repository.", 'info')
    return redirect(url_for('repository', repo_id=repo_id))

@app.route('/link_cves/<int:repo_id>', methods=['POST'])
def link_cves(repo_id):
    session = g.db_session
    repo = session.get(Repository, repo_id)
    if repo:
        scan = Scan(repository_id=repo.id, scan_type='cve-linking', status='queued')
        session.add(scan)
        session.commit()
        job = q.enqueue('src.worker.link_cves_to_findings_job', repo_id, scan.id)
        scan.job_id = job.id
        session.commit()
        flash(f"CVE linking initiated for repository.", 'info')
    return redirect(url_for('repository', repo_id=repo_id))

@app.route('/rerun_scan/<int:scan_id>', methods=['POST'])
def rerun_scan(scan_id):
    session = g.db_session
    scan = session.get(Scan, scan_id)
    if scan:
        if scan.scan_type == 'commit':
            job = q.enqueue('src.worker.run_analysis_job', scan.repository.url, scan.triggering_commit_hash, scan.repository.id, auto_patch=scan.auto_patch_enabled)
        else:
            job = q.enqueue('src.worker.run_deep_scan_job', scan.repository.url, auto_patch=scan.auto_patch_enabled)
        scan.job_id = job.id
        scan.status = 'queued'
        session.commit()
        flash(f"Rerunning scan {scan.id} for '{scan.repository.name}'.", 'info')
    return redirect(url_for('repository', repo_id=scan.repository.id))
    
@app.route('/generate_patch/<int:finding_id>', methods=['POST'])
def generate_patch(finding_id):
    session = g.db_session
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
    orchestrator.rewrite_remediation(finding_id)
    flash(f"Patch generation initiated for Finding #{finding_id}.", 'info')
    return redirect(url_for('finding', finding_id=finding_id))


# ...
@app.route('/stop_scan/<int:scan_id>', methods=['POST'])
def stop_scan(scan_id):
    session = g.db_session
    scan = session.get(Scan, scan_id)
    if scan and scan.job_id:
        job = q.fetch_job(scan.job_id)
        if job:
            job.cancel()
            scan.status = ScanStatus.FAILED
            session.commit()
            flash(f"Scan {scan_id} stopped.", 'success')
        else:
            flash(f"Job {scan.job_id} not found in queue.", 'error')
    else:
        flash(f"Scan {scan_id} not found or has no job ID.", 'error')
    return redirect(url_for('scans'))

@app.route('/delete_scan/<int:scan_id>', methods=['POST', 'DELETE'])
def delete_scan(scan_id):
    session = g.db_session
    scan = session.get(Scan, scan_id)
    if scan:
        session.delete(scan)
        session.commit()
        flash(f"Scan {scan_id} deleted.", 'success')
    else:
        flash(f"Scan {scan_id} not found.", 'error')
    return redirect(url_for('scans'))

@app.route('/mark_scan_failed/<int:scan_id>', methods=['POST'])
def mark_scan_failed(scan_id):
    session = g.db_session
    scan = session.get(Scan, scan_id)
    if scan:
        scan.status = ScanStatus.FAILED
        session.commit()
        flash(f"Scan {scan_id} marked as failed.", 'success')
    else:
        flash(f"Scan {scan_id} not found.", 'error')
    return redirect(url_for('scans'))

@app.route('/interpret_quality_metrics/<int:metric_id>')
def interpret_quality_metrics(metric_id):
    session = g.db_session
    metric = session.get(QualityMetric, metric_id)
    if not metric:
        flash("Metric not found.", "error")
        return redirect(url_for('quality', repo_id=metric.scan.repository.id))

    if metric.interpretation:
        return redirect(url_for('quality_interpretation', interpretation_id=metric.interpretation.id))

    orchestrator = Orchestrator(None, session, None)
    interpretation_text = orchestrator.llm_service.interpret_quality_metrics(metric)
    
    new_interpretation = QualityInterpretation(quality_metric_id=metric.id, interpretation=interpretation_text)
    session.add(new_interpretation)
    session.commit()

    return redirect(url_for('quality_interpretation', interpretation_id=new_interpretation.id))


@app.route('/quality_interpretation/<int:interpretation_id>')
def quality_interpretation(interpretation_id):
    session = g.db_session
    interpretation = session.get(QualityInterpretation, interpretation_id)
    metric = interpretation.quality_metric
    chat_history = session.query(ChatMessage).filter_by(quality_interpretation_id=interpretation_id).order_by(ChatMessage.created_at).all()
    return render_template('quality_interpretation.html', interpretation=interpretation, metric=metric, chat_history=chat_history)


@app.route('/chat_with_quality_interpretation/<int:interpretation_id>', methods=['POST'])
def chat_with_quality_interpretation(interpretation_id):
    data = request.get_json()
    message = data.get('message')
    if not message:
        return jsonify({'error': 'Message is required'}), 400

    session = g.db_session
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session, None)
    response = orchestrator.chat_with_quality_interpretation(interpretation_id, message)
    return jsonify({'response': response})

@app.route('/reset_chat/<string:chat_type>/<int:chat_id>', methods=['POST'])
def reset_chat(chat_type, chat_id):
    session = g.db_session
    if chat_type == 'finding':
        messages = session.query(ChatMessage).filter_by(finding_id=chat_id).all()
    elif chat_type == 'quality':
        messages = session.query(ChatMessage).filter_by(quality_interpretation_id=chat_id).all()
    else:
        return jsonify({'status': 'error', 'message': 'Invalid chat type'}), 400

    for message in messages:
        session.delete(message)
    session.commit()

    return jsonify({'status': 'success', 'message': 'Chat history has been reset.'})

@app.route('/scan/<int:scan_id>')
def scan(scan_id):
    session = g.db_session
    scan = session.get(Scan, scan_id)
    if not scan:
        flash(f"Scan with ID {scan_id} not found.", "error")
        return redirect(url_for('index'))
    app.logger.info(f"Scan type for scan {scan_id} is {scan.scan_type}")

    if scan.scan_type == 'quality':
        sort_by = request.args.get('sort_by', 'file_path')
        sort_order = request.args.get('sort_order', 'asc')
        
        metrics = sorted(scan.quality_metrics, key=lambda m: getattr(m, sort_by), reverse=sort_order == 'desc')
        
        return render_template('quality.html', repo=scan.repository, metrics=metrics, sort_by=sort_by, sort_order=sort_order, scan_id=scan_id)
    else:
        severity_filter = request.args.get('severity')
        scanner_filter = request.args.get('scanner')
        sort_by = request.args.get('sort_by', 'severity')
        sort_order = request.args.get('sort_order', 'desc')
        keyword = request.args.get('keyword')

        findings_query = session.query(Finding).filter(Finding.scan_id == scan_id)

        if severity_filter:
            findings_query = findings_query.filter(Finding.severity == severity_filter)
        
        if scanner_filter:
            findings_query = findings_query.filter(Finding.description.like(f"{scanner_filter}:%"))
        
        if keyword:
            findings_query = findings_query.filter(Finding.description.ilike(f"%{keyword}%"))

        if sort_by == 'severity':
            severity_order = [
                'CRITICAL',
                'HIGH',
 'MEDIUM',
 'LOW',
 'UNKNOWN'
            ]
            # Create a CASE statement for custom sorting
            case_statement = case(
                *[
                    (Finding.severity == severity, index)
                    for index, severity in enumerate(severity_order)
                ],
                else_=len(severity_order) # Unknown severities go last
            )
            if sort_order == 'desc':
                findings_query = findings_query.order_by(case_statement.desc())
            else:
                findings_query = findings_query.order_by(case_statement.asc())
        elif sort_by == 'file':
            if sort_order == 'desc':
                findings_query = findings_query.order_by(Finding.file_path.desc())
            else:
                findings_query = findings_query.order_by(Finding.file_path.asc())

        findings = findings_query.all()
        findings_count = len(findings)

        findings_by_file = defaultdict(list)
        for finding in findings:
            findings_by_file[finding.file_path or "General"].append(finding)

        return render_template('scan.html', scan=scan, findings_by_file=findings_by_file, 
                               findings_count=findings_count,
                               severity_filter=severity_filter, scanner_filter=scanner_filter,
                               sort_by=sort_by, sort_order=sort_order, keyword=keyword)

@app.route('/finding/<int:finding_id>')
def finding(finding_id):
    session = g.db_session
    finding = session.get(Finding, finding_id)
    if not finding:
        flash(f"Finding with ID {finding_id} not found.", "error")
        return redirect(url_for('index'))
    chat_history = session.query(ChatMessage).filter_by(finding_id=finding_id).order_by(ChatMessage.created_at).all()
    
    if finding:
        description_no_paren = finding.description.replace('(', '').replace(')', '')
        url_match = re.search(r'https?://\S+', description_no_paren)
        
        if url_match:
            url = url_match.group(0)
            text = finding.description.replace(f'({url})', '').strip()
            finding.description_text = text
            finding.description_url = url
            
            # Extract rule ID
            if 'semgrep.dev' in url:
                finding.rule_id = url.split('/')[-1]
            elif 'bandit.readthedocs.io' in url:
                finding.rule_id = url.split('/')[-1].replace('.html', '')
            else:
                finding.rule_id = 'doc'
        else:
            finding.description_text = finding.description
            finding.description_url = None
            finding.rule_id = None
            
    return render_template('finding.html', finding=finding, chat_history=chat_history)

@app.route('/finding/<int:finding_id>/search_cve', methods=['POST'])
def search_cve(finding_id):
    session = g.db_session
    finding = session.get(Finding, finding_id)
    if finding:
        orchestrator = Orchestrator(None, session, di.google_web_search)
        orchestrator.search_cve_for_finding(finding)
        flash("CVE search initiated. The finding will be updated shortly.", 'info')
    return redirect(url_for('finding', finding_id=finding_id))

@app.route('/recheck_finding/<int:finding_id>', methods=['POST'])
def recheck_finding(finding_id):
    session = g.db_session
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
    orchestrator.recheck_finding(finding_id)
    return redirect(url_for('finding', finding_id=finding_id))

@app.route('/rewrite_remediation/<int:finding_id>', methods=['POST'])
def rewrite_remediation(finding_id):
    session = g.db_session
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
    orchestrator.rewrite_remediation(finding_id)
    return redirect(url_for('finding', finding_id=finding_id))

@app.route('/update_patch/<int:finding_id>', methods=['POST'])
def update_patch(finding_id):
    patch_diff = request.form['patch_diff']
    session = g.db_session
    patch = session.query(Patch).filter_by(finding_id=finding_id).first()
    if patch:
        patch.generated_patch_diff = patch_diff
        session.commit()
    return redirect(url_for('finding', finding_id=finding_id))

@app.route('/chat/<int:finding_id>', methods=['POST'])
def chat(finding_id):
    message = request.json['message']
    session = g.db_session
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
    response = orchestrator.chat_with_finding(finding_id, message)
    return {'response': response}

@app.route('/ci/scan', methods=['POST'])
def ci_scan():
    repo_url = request.json['repo_url']
    commit_hash = request.json.get('commit_hash')

    session = g.db_session
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session, di.google_web_search)
    
    repository = session.query(Repository).filter_by(url=repo_url).first()
    if not repository:
        primary_branch = vcs_service.get_primary_branch(repo_url)
        if not primary_branch:
            return jsonify({'status': 'failure', 'message': f'Could not determine primary branch for {repo_url}.'}), 400
        repository = Repository(name=repo_url.split('/')[-1], url=repo_url, primary_branch=primary_branch)
        session.add(repository)
        session.commit()

    if not commit_hash:
        commit_hash = vcs_service.get_latest_commit_hash(repo_url, repository.primary_branch)
        if not commit_hash:
            return jsonify({'status': 'failure', 'message': f'Could not get latest commit hash for {repo_url}.'}), 400

    job = q.enqueue('src.worker.run_analysis_job', repo_url, commit_hash, repository.id, auto_patch=False)
    scan = Scan(repository_id=repository.id, scan_type='commit', status='queued', job_id=job.id, triggering_commit_hash=commit_hash)
    session.add(scan)
    session.commit()

    return jsonify({'status': 'success', 'message': f'Scan initiated for {repo_url} at commit {commit_hash}.'})

def synchronize_scan_statuses(session): # <--- ACCEPT SESSION AS AN ARGUMENT
    """Synchronizes the scan statuses with the RQ queue."""
    # No longer creates or closes its own session. It uses the one passed to it.
    with app.app_context(): # Keep the app context for logging or other extensions
        scans = session.query(Scan).filter(Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED])).all()
        app.logger.info(f"Found {len(scans)} running or queued scans to synchronize.")
        for scan in scans:
            if scan.job_id:
                job = q.fetch_job(scan.job_id)
                app.logger.info(f"Checking job {scan.job_id} for scan {scan.id}. Job status: {job.get_status() if job else 'not found'}")
                if job is None or job.get_status() == 'failed':
                    app.logger.info(f"Updating scan {scan.id} to FAILED.")
                    scan.status = ScanStatus.FAILED
                    session.commit()
            else:
                app.logger.info(f"Scan {scan.id} has no job ID, marking as FAILED.")
                scan.status = ScanStatus.FAILED
                session.commit()
        app.logger.info("Synchronization complete.")

def periodic_sync():
    """Periodically synchronizes the scan statuses."""
    import time
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    while True:
        session = None # Define session outside the try block
        try:
            logging.info("Periodic Sync: Creating new DB session...")
            # Create a new session for this run
            session = get_session()()
            # Pass the session to the sync function
            synchronize_scan_statuses(session)
        except Exception as e:
            logging.error("An error occurred in the periodic sync process.", exc_info=True)
        finally:
            # This is critical: always close the session to prevent leaks
            if session:
                session.close()
                logging.info("Periodic Sync: DB session closed.")
        time.sleep(10)

@app.before_request
def before_request():
    """
    Get a session from the pool and store it in the application context.
    """
    g.db_session = get_session()()

@app.teardown_appcontext
def shutdown_session(exception=None):
    """
    Remove the database session at the end of the request or when the app shuts down.
    """
    db_session = g.pop('db_session', None)
    if db_session is not None:
        db_session.close()
