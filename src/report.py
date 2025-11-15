import logging
from src.database import get_session, Finding

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_report():
    """Queries the database and generates an HTML report of findings."""
    Session = get_session()
    session = Session()

    try:
        logging.info("--- Generating V-Raptor Findings Report ---")

        all_findings = session.query(Finding).all()

        if not all_findings:
            logging.info("No findings found in the database.")
            return

        # Basic HTML structure
        html = """
        <!DOCTYPE html>
        <html>
        <head>
        <title>V-Raptor Findings Report</title>
        <style>
            body { font-family: sans-serif; }
            h1 { color: #333; }
            .repo { border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
            .finding { border-top: 1px solid #eee; padding-top: 10px; margin-top: 10px; }
            .finding h3 { margin-top: 0; }
            pre { background-color: #f4f4f4; padding: 10px; border-radius: 3px; white-space: pre-wrap; }
        </style>
        </head>
        <body>
        <h1>V-Raptor Findings Report</h1>
        """

        findings_by_repo = {}
        for finding in all_findings:
            repo_name = finding.scan.repository.name
            if repo_name not in findings_by_repo:
                findings_by_repo[repo_name] = []
            findings_by_repo[repo_name].append(finding)

        for repo_name, findings in findings_by_repo.items():
            html += f'<div class="repo"><h2>Repository: {repo_name} ({len(findings)} findings)</h2>'
            for finding in findings:
                html += f'''
                <div class="finding">
                    <h3>Finding ID: {finding.id}</h3>
                    <p><strong>Description:</strong> {finding.description}</p>
                    <p><strong>File:</strong> {finding.file_path}:{finding.line_number}</p>
                    <p><strong>Severity:</strong> {finding.severity}</p>
                    <p><strong>Status:</strong> {finding.status}</p>
                    <p><strong>Confidence:</strong> {finding.confidence_score}</p>
                    <h4>Code Snippet:</h4>
                    <pre><code>{finding.code_snippet}</code></pre>
                '''
                for evidence in finding.evidence:
                    html += f'''
                    <h4>Evidence ({evidence.type}):</h4>
                    <pre><code>{evidence.content}</code></pre>
                    '''
                html += '</div>'
            html += '</div>'

        html += """
        </body>
        </html>
        """

        with open("report.html", "w") as f:
            f.write(html)

        logging.info("Report generated: report.html")

    finally:
        session.close()

if __name__ == '__main__':
    generate_report()