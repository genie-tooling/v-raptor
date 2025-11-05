from flask import Flask, render_template, request, redirect, url_for
from .database import get_session, Repository, Scan, Finding, Patch
from .orchestrator import Orchestrator
from .vcs import VCSService

app = Flask(__name__)

@app.route('/')
def index():
    session = get_session()()
    repos = session.query(Repository).all()
    return render_template('index.html', repos=repos)

@app.route('/add_repo', methods=['POST'])
def add_repo():
    repo_url = request.form['repo_url']
    vcs_service = VCSService(git_provider='github', token='')
    validated_url = vcs_service.is_valid_git_url(repo_url)
    if validated_url:
        session = get_session()()
        repo_name = validated_url.split('/')[-1].replace('.git', '')
        new_repo = Repository(name=repo_name, url=validated_url)
        session.add(new_repo)
        session.commit()
    else:
        # Handle invalid URL - maybe flash a message
        pass
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

@app.route('/run_scan/<int:repo_id>', methods=['POST'])
def run_scan(repo_id):
    session = get_session()()
    repo = session.query(Repository).get(repo_id)
    if repo:
        vcs_service = VCSService(git_provider='github', token='')
        orchestrator = Orchestrator(vcs_service, session)
        orchestrator.run_deep_scan(repo.url)
    return redirect(url_for('repository', repo_id=repo_id))

@app.route('/rerun_scan/<int:scan_id>', methods=['POST'])
def rerun_scan(scan_id):
    session = get_session()()
    scan = session.query(Scan).get(scan_id)
    if scan:
        vcs_service = VCSService(git_provider='github', token='')
        orchestrator = Orchestrator(vcs_service, session)
        if scan.scan_type == 'commit':
            orchestrator.run_analysis_on_commit(scan.repository.url, scan.triggering_commit_hash, scan.repository.id)
        elif scan.scan_type in ['dependency', 'configuration']:
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
    return render_template('finding.html', finding=finding)

@app.route('/recheck_finding/<int:finding_id>', methods=['POST'])
def recheck_finding(finding_id):
    session = get_session()()
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session)
    orchestrator.recheck_finding(finding_id)
    return redirect(url_for('finding', finding_id=finding_id))

@app.route('/rewrite_remediation/<int:finding_id>', methods=['POST'])
def rewrite_remediation(finding_id):
    session = get_session()()
    vcs_service = VCSService(git_provider='github', token='')
    orchestrator = Orchestrator(vcs_service, session)
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

if __name__ == '__main__':
    app.run(debug=True)
