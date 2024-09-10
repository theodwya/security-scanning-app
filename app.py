import os
import json
import subprocess
import logging
import magic  
import tarfile
import shutil
import tempfile
from flask import Flask, jsonify, request, render_template, send_from_directory, abort
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurable folders via environment variables with fallbacks to default temporary directories
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', tempfile.mkdtemp())
SCAN_RESULTS_FOLDER = os.getenv('SCAN_RESULTS_FOLDER', tempfile.mkdtemp())
YARA_RULES_PATH = os.getenv('YARA_RULES_PATH', '/opt/yara/malware_index.yar')  # Update with the correct path or use environment variable

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SCAN_RESULTS_FOLDER'] = SCAN_RESULTS_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 * 1024  # 5GB max file size
app.secret_key = 'supersecretkey'  # Set a secure key for sessions

# Ensure necessary directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SCAN_RESULTS_FOLDER'], exist_ok=True)

# Path for storing review data
REVIEW_FILE_PATH = os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'review.json')

# Ensure the review file exists
if not os.path.exists(REVIEW_FILE_PATH):
    with open(REVIEW_FILE_PATH, 'w') as file:
        json.dump([], file)  # Initialize as an empty list

# Initialize file type detector
try:
    mime = magic.Magic(mime=True)  # This assumes libmagic is properly installed
except Exception as e:
    logger.error(f"Failed to initialize magic: {e}")
    mime = None

def sanitize_input(input_value):
    """Sanitize user inputs to prevent command injection and path traversal attacks."""
    if '..' in input_value or '/' in input_value or '\\' in input_value:
        logger.error(f"Invalid input detected: {input_value}")
        abort(400, description="Invalid input detected.")
    return input_value

def extract_files(filepath, dest):
    """Extract .tar, .tgz, .tar.gz files."""
    try:
        if tarfile.is_tarfile(filepath):
            with tarfile.open(filepath, 'r:*') as tar:
                tar.extractall(path=dest)
                logger.info(f"Extracted {filepath} to {dest}")
        else:
            logger.warning(f"{filepath} is not a valid tar archive.")
    except Exception as e:
        logger.error(f"Failed to extract {filepath}: {e}")

def handle_virus_detection(scan_type, path):
    """Log virus detection for manual review."""
    logger.error(f"Potential virus detected in {scan_type} on: {path}. Requires manual review.")

    # Create a review entry
    review_entry = {
        'scan_type': scan_type,
        'path': path,
        'status': 'Pending Review'
    }

    # Append the review entry to the JSON file
    try:
        with open(REVIEW_FILE_PATH, 'r+') as file:
            data = json.load(file)  # Load existing data
            data.append(review_entry)  # Append new entry
            file.seek(0)  # Move to the beginning of the file
            json.dump(data, file, indent=4)  # Write updated data
        logger.info(f"Review entry added for {path}.")
    except Exception as e:
        logger.error(f"Failed to update review log: {e}")

def get_review_data():
    """Retrieve the list of scan results marked for review."""
    try:
        with open(REVIEW_FILE_PATH, 'r') as file:
            return json.load(file)
    except Exception as e:
        logger.error(f"Failed to load review data: {e}")
        return []

@app.route('/review')
def review():
    """Display flagged scan results for manual review."""
    review_data = get_review_data()
    return render_template('review.html', review_data=review_data)

@app.route('/mark_reviewed/<int:index>', methods=['POST'])
def mark_reviewed(index):
    """Mark a review item as reviewed."""
    try:
        with open(REVIEW_FILE_PATH, 'r+') as file:
            data = json.load(file)
            data[index]['status'] = 'Reviewed'
            file.seek(0)
            json.dump(data, file, indent=4)
        return jsonify({'message': 'Marked as reviewed'}), 200
    except Exception as e:
        logger.error(f"Failed to mark as reviewed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/delete_review/<int:index>', methods=['POST'])
def delete_review(index):
    """Delete a review item."""
    try:
        with open(REVIEW_FILE_PATH, 'r+') as file:
            data = json.load(file)
            data.pop(index)
            file.seek(0)
            file.truncate()  # Remove remaining old data
            json.dump(data, file, indent=4)
        return jsonify({'message': 'Entry deleted'}), 200
    except Exception as e:
        logger.error(f"Failed to delete review: {e}")
        return jsonify({'error': str(e)}), 500

def run_yara_scan(target_dir):
    """Run YARA scan on the target directory."""
    try:
        result = subprocess.run(['yara', '-r', YARA_RULES_PATH, target_dir], capture_output=True, text=True, check=True)
        logger.info(f"YARA Scan Results: {result.stdout}")
        if "matches" in result.stdout:
            handle_virus_detection('YARA', target_dir)
        return {'path': target_dir, 'scan_type': 'YARA', 'severity': 'info', 'details': result.stdout}
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running YARA: {e.stderr}")
        return {'path': target_dir, 'scan_type': 'YARA', 'severity': 'error', 'details': f"Error running YARA: {e.stderr}"}

def run_trivy_scan(command, output_path):
    """Run a Trivy scan command and handle output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        with open(output_path, 'w') as f:
            f.write(result.stdout)
        scan_result = result.stdout.lower()
        if 'virus' in scan_result or 'malware' in scan_result:
            handle_virus_detection('Trivy', output_path)
        return json.loads(result.stdout)  # Return full JSON result
    except subprocess.CalledProcessError as e:
        logger.error(f"Trivy scan failed: {e.stderr}")
        return {'error': f"Error running Trivy scan: {e.stderr}"}

def run_trivy_image_scan(image_name):
    """Run a Trivy image scan."""
    scan_output_path = os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'trivy_image_scan.json')
    logger.info(f"Running Trivy image scan on: {image_name}")
    command = ['trivy', 'image', image_name, '--format', 'json']
    return run_trivy_scan(command, scan_output_path)

def run_trivy_fs_scan(target_path):
    """Run Trivy filesystem scan."""
    scan_output_path = os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'trivy_fs_scan.json')
    logger.info(f"Running Trivy filesystem scan on: {target_path}")
    command = ['trivy', 'fs', target_path, '--format', 'json']
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        with open(scan_output_path, 'w') as f:
            f.write(result.stdout)  # Save the full JSON results to a file
        logger.info("Trivy filesystem scan completed successfully.")
        return json.loads(result.stdout)  # Return the full JSON result
    except subprocess.CalledProcessError as e:
        logger.error(f"Trivy scan failed: {e.stderr}")
        return {'error': f"Error running Trivy scan: {e.stderr}"}

def run_trivy_repo_scan(git_repo_url):
    """Run Trivy scan on a Git repository."""
    logger.info(f"Running Trivy remote Git scan on: {git_repo_url}")
    scan_output_path = os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'trivy_repo_scan.json')
    command = ['trivy', 'repo', git_repo_url, '--format', 'json']
    try:
        return run_trivy_scan(command, scan_output_path)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running Trivy Git scan: {e.stderr}")
        return {'error': f"Error running Trivy Git scan: {e.stderr}"}
    except Exception as e:
        logger.error(f"Unexpected error during Trivy Git scan: {e}")
        return {'error': f"Unexpected error: {e}"}

def clone_git_repo(git_repo_url, clone_path):
    """Clone a Git repository to the specified path."""
    logger.info(f"Cloning Git repository: {git_repo_url}")
    try:
        subprocess.run(['git', 'clone', git_repo_url, clone_path], check=True)
        logger.info(f"Repository cloned to: {clone_path}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone repository: {e}")
        return False

def run_grype_image_scan(image_name):
    """Run Grype scan on a Docker image."""
    scan_output_path = os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'grype_image_scan.json')
    logger.info(f"Running Grype image scan on: {image_name}")
    try:
        result = subprocess.run(
            ['grype', f'docker:{image_name}', '--output', 'json'],
            capture_output=True, text=True, check=True
        )
        with open(scan_output_path, 'w') as f:
            f.write(result.stdout)

        scan_result = result.stdout.lower()
        if 'virus' in scan_result or 'malware' in scan_result:
            handle_virus_detection('Grype', image_name)

        return json.loads(result.stdout)  # Return full JSON result
    except subprocess.CalledProcessError as e:
        logger.error(f"Grype image scan failed: {e.stderr}")
        return {'error': f"Error running Grype image scan: {e.stderr}"}

def run_clamav_scan(path):
    """Run ClamAV scan on a file or directory."""
    if os.path.isdir(path):
        # Scan all files recursively in the directory
        scan_results = []
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_results.append(scan_file_with_clamav(file_path))
        return scan_results
    elif os.path.isfile(path):
        # Directly scan the file
        return [scan_file_with_clamav(path)]
    else:
        logger.warning(f"Skipping ClamAV scan: {path} is not a valid file or directory path.")
        return [{'path': path, 'scan_type': 'ClamAV', 'severity': 'warning', 'details': 'Invalid path.'}]

def scan_file_with_clamav(file_path):
    """Scan a single file with ClamAV and return the result."""
    scan_output_path = os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'clamav_scan.log')
    logger.info(f"Running ClamAV scan on: {file_path}")
    try:
        result = subprocess.run(
            ['clamscan', '--log', scan_output_path, file_path],
            capture_output=True, text=True, check=True
        )
        if 'Infected files: 0' not in result.stdout:
            handle_virus_detection('ClamAV', file_path)
        return {'path': file_path, 'scan_type': 'ClamAV', 'severity': 'info', 'details': result.stdout}
    except subprocess.CalledProcessError as e:
        logger.error(f"ClamAV scan failed: {e.stderr}")
        return {'path': file_path, 'scan_type': 'ClamAV', 'severity': 'error', 'details': f"Error running ClamAV scan: {e.stderr}"}

def run_clamav_docker_image_scan(image_name):
    """Run ClamAV scan on Docker images by extracting the image contents."""
    image_tar_path = f'/tmp/{image_name.replace("/", "_")}.tar'
    extract_path = '/tmp/extracted_image'
    logger.info(f"Saving Docker image {image_name} to {image_tar_path}")
    try:
        subprocess.run(['docker', 'save', image_name, '-o', image_tar_path], check=True)
        extract_files(image_tar_path, extract_path)
        clamav_result = run_clamav_scan(extract_path)
        if any("infected" in item.get('details', '').lower() for item in clamav_result):
            logger.critical(f"Virus detected in Docker image {image_name}! Shutting down.")
            os.system("shutdown now -h")
        return clamav_result
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to scan Docker image {image_name} with ClamAV: {e.stderr}")
        return [{'error': f"Error running ClamAV scan on Docker image: {e.stderr}"}]

def detect_file_type(file_path):
    """Detect the type of a file using libmagic."""
    if mime:
        try:
            file_type = mime.from_file(file_path)
            logger.info(f"Detected file type: {file_type}")
            return file_type
        except Exception as e:
            logger.error(f"Failed to detect file type: {e}")
            return "Unknown file type"
    else:
        logger.error("libmagic not initialized.")
        return "libmagic not available"

def format_scan_result(result, scan_type):
    """Ensure each result has 'path', 'scan_type', 'severity', and 'details'."""
    if result is None:
        logger.error("Received NoneType in scan results.")
        return {
            'path': 'Unknown path',
            'scan_type': scan_type,
            'severity': 'unknown',
            'details': 'No data available'
        }

    if isinstance(result, dict):
        # Ensure all expected fields are present
        return {
            'path': result.get('path', 'Unknown path'),
            'scan_type': result.get('scan_type', scan_type),
            'severity': result.get('severity', 'unknown'),
            'details': result.get('details', 'No details provided')
        }
    elif isinstance(result, list):
        # Recursively format each item in the list
        return [format_scan_result(item, scan_type) for item in result]
    elif isinstance(result, str):
        return {
            'path': 'Unknown path',
            'scan_type': scan_type,
            'severity': 'unknown',
            'details': result
        }
    else:
        logger.error(f"Unexpected result type: {type(result)}")
        return {
            'path': 'Unknown path',
            'scan_type': scan_type,
            'severity': 'error',
            'details': 'Unexpected result type'
        }

def perform_scan_tasks(scan_tasks):
    """Execute scan tasks in parallel and collect results."""
    results = []
    with ThreadPoolExecutor() as executor:
        future_to_task = {executor.submit(task): task for task in scan_tasks}
        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                result = future.result()
                results.extend(result if isinstance(result, list) else [result])
            except Exception as exc:
                logger.error(f"Task {task} generated an exception: {exc}")
                results.append({'error': f"Error: {exc}"})
    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        image_name = request.form.get('image_name')
        git_repo_url = request.form.get('git_url')
        files = request.files.getlist('file')
        scan_results = []  # Initialize scan_results

        if scan_type == 'filesystem':
            for file in files:
                filename = secure_filename(file.filename)
                if not filename:
                    logger.error("No filename provided for file upload.")
                    scan_results.append("Error: No valid filename provided.")
                    continue

                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    file.save(file_path)
                    logger.info(f"File saved to {file_path}")
                except Exception as e:
                    logger.error(f"Failed to save file: {e}")
                    scan_results.append(f"Error saving file {filename}: {e}")
                    continue

                try:
                    file_type = detect_file_type(file_path)
                except Exception as e:
                    scan_results.append(f"Error detecting file type: {e}")
                    continue

                # Perform the filesystem scan
                full_scan_result = run_trivy_fs_scan(file_path)
                scan_results.append(format_scan_result(full_scan_result, 'filesystem'))

        if scan_type == 'git' and git_repo_url:
            # Correct function call and handle output
            try:
                logger.info(f"Running Trivy remote Git scan on: {git_repo_url}")
                trivy_repo_result = run_trivy_repo_scan(git_repo_url)
                scan_results.append(format_scan_result(trivy_repo_result, 'git'))
                logger.info(f"Git repository scan completed for: {git_repo_url}")
            except Exception as e:
                scan_results.append({'error': f"Error running Trivy Git scan: {e}"})

            # Clone the repo and run further scans
            clone_path = os.path.join(app.config['UPLOAD_FOLDER'], 'cloned_repo')
            if clone_git_repo(git_repo_url, clone_path):
                scan_results.extend(run_clamav_scan(clone_path))  # Correctly handles directories now
                scan_results.append(run_yara_scan(clone_path))  # Include YARA scan
                trivy_scan_result = run_trivy_scan(['trivy', 'fs', clone_path, '--format', 'json'],
                                                   os.path.join(app.config['SCAN_RESULTS_FOLDER'], 'trivy_fs_scan.json'))
                scan_results.append(format_scan_result(trivy_scan_result, 'filesystem'))
                shutil.rmtree(clone_path)  # Clean up after scanning

        elif scan_type == 'image' and image_name:
            # Define scan tasks for image scans
            scan_tasks = [
                lambda: run_trivy_image_scan(image_name),
                lambda: run_grype_image_scan(image_name),
                lambda: run_clamav_docker_image_scan(image_name)
            ]

            clamav_path = f'/var/lib/docker/images/{image_name}'
            if os.path.exists(clamav_path):
                scan_tasks.append(lambda: run_clamav_scan(clamav_path))

            # Run scans in parallel
            scan_results.extend(perform_scan_tasks(scan_tasks))

        # Format scan results consistently
        formatted_results = []
        for result in scan_results:
            if isinstance(result, list):
                formatted_results.extend([format_scan_result(item, scan_type) for item in result])
            else:
                formatted_results.append(format_scan_result(result, scan_type))

        # Ensure scan results are passed to the template
        return render_template('index.html', scan_results=formatted_results)

    return render_template('index.html')

@app.route('/download/<filename>')
def download_file(filename):
    """Serve files for download from the output folder."""
    sanitized_filename = sanitize_input(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], sanitized_filename)

@app.route('/download')
def download_files():
    """List available files for download."""
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('download.html', files=files)

if __name__ == "__main__":
    logger.info("Starting Flask application on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000)
