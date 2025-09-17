from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, session, flash
import pandas as pd
import os
from werkzeug.utils import secure_filename
import json
import msal
import requests
from io import BytesIO
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
import ipaddress
from datetime import datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'  # Change this in production!

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Authentication Configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# User management file
USERS_FILE = 'users.json'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, username, role='viewer', active=True):
        self.id = username
        self.username = username
        self.role = role
        self.active = active
    
    def is_active(self):
        return self.active

@login_manager.user_loader
def load_user(username):
    users = load_users()
    if username in users:
        user_data = users[username]
        return User(username, user_data.get('role', 'viewer'), user_data.get('active', True))
    return None

def load_users():
    """Load users from JSON file"""
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        else:
            # Create default admin user if no users file exists
            default_users = {
                'admin': {
                    'password_hash': bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                    'role': 'admin',
                    'active': True,
                    'created_at': datetime.now().isoformat()
                }
            }
            save_users(default_users)
            return default_users
    except Exception as e:
        print(f"Error loading users: {e}")
        return {}

def save_users(users):
    """Save users to JSON file"""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        print(f"Error saving users: {e}")

def is_local_network(ip):
    """Check if IP address is from local network"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Check for private networks and localhost
        return (ip_obj.is_private or 
                ip_obj.is_loopback or 
                str(ip_obj) == '127.0.0.1' or
                str(ip_obj).startswith('192.168.') or
                str(ip_obj).startswith('10.') or
                str(ip_obj).startswith('172.'))
    except:
        return False

def auth_required(f):
    """Custom decorator that bypasses authentication for local network"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get client IP
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        # Allow local network access without authentication
        if is_local_network(client_ip):
            return f(*args, **kwargs)
        
        # Require authentication for external access
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    """Decorator to check user role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
            if ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Allow local network access without role check
            if is_local_network(client_ip):
                return f(*args, **kwargs)
            
            # Check authentication and role for external access
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            role_hierarchy = {'viewer': 1, 'editor': 2, 'admin': 3}
            user_level = role_hierarchy.get(current_user.role, 0)
            required_level = role_hierarchy.get(required_role, 3)
            
            if user_level < required_level:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Global variables to store current data
current_data = None
current_blockers = []
current_prep_tasks = []

# SharePoint Configuration - TO BE CONFIGURED WITH YOUR CREDENTIALS
SHAREPOINT_CONFIG = {
    'client_id': 'YOUR_CLIENT_ID_HERE',  # Replace with your Azure App Registration Client ID
    'client_secret': 'YOUR_CLIENT_SECRET_HERE',  # Replace with your Azure App Registration Client Secret
    'tenant_id': 'YOUR_TENANT_ID_HERE',  # Replace with your Azure AD Tenant ID
    'sharepoint_url': 'https://corpdir.sharepoint.com/:x:/r/sites/DWT_TransformationDC-GLCLCs/Freigegebene%20Dokumente/General/01%20Data%20gathering/Telnet%20Testplan/Telnet%20Test%2001.xlsx?d=w42ba8494591540159c0797c136ce3583&csf=1&web=1&e=F1WSSB',
    'site_url': 'https://corpdir.sharepoint.com/sites/DWT_TransformationDC-GLCLCs',
    'file_path': '/Freigegebene Dokumente/General/01 Data gathering/Telnet Testplan/Telnet Test 01.xlsx'
}

def auto_create_blocker_if_needed(blocker_name, test_item):
    """Auto-create a blocker if it doesn't exist"""
    global current_blockers
    
    if not blocker_name or blocker_name.strip() == '':
        return
    
    # Check if blocker already exists
    existing_blocker = next((b for b in current_blockers if b['name'] == blocker_name), None)
    if existing_blocker:
        return  # Blocker already exists
    
    # Create new blocker with smart defaults
    from datetime import datetime
    next_id = max([item['id'] for item in current_blockers], default=0) + 1
    
    new_blocker = {
        'id': next_id,
        'name': blocker_name,
        'description': f"Blocker for {test_item['test']}",
        'responsible': test_item.get('responsible', ''),
        'start_date': datetime.now().strftime('%d.%m.%Y'),
        'priority': 'medium',
        'resolution_status': 'open'
    }
    
    current_blockers.append(new_blocker)

def get_affected_tests(blocker_name):
    """Get all tests affected by a specific blocker"""
    global current_data
    
    if not current_data:
        return []
    
    affected_tests = []
    for test in current_data:
        if test.get('blocker') == blocker_name:
            affected_tests.append({
                'id': test['id'],
                'test': test['test'],
                'responsible': test['responsible'],
                'status': test['status']
            })
    
    return affected_tests

def cleanup_unused_blocker(blocker_name):
    """Remove blocker if no tests are using it anymore"""
    global current_data, current_blockers
    
    if not current_data or not blocker_name:
        return
    
    # Check if any test still references this blocker
    is_still_used = any(test.get('blocker') == blocker_name for test in current_data)
    
    # If no test uses this blocker anymore, remove it from the blocker list
    if not is_still_used:
        current_blockers[:] = [blocker for blocker in current_blockers if blocker['name'] != blocker_name]

def sync_existing_blockers():
    """Scan all existing tests and create missing blocker entries"""
    global current_data, current_blockers
    
    if not current_data:
        return
    
    # Get all unique blocker names from tests
    existing_blocker_names = set()
    for test in current_data:
        blocker_name = test.get('blocker', '').strip()
        if blocker_name:
            existing_blocker_names.add(blocker_name)
    
    # Get all existing blocker names in the blocker list
    blocker_list_names = set(blocker['name'] for blocker in current_blockers)
    
    # Find missing blockers
    missing_blockers = existing_blocker_names - blocker_list_names
    
    # Create missing blocker entries
    for blocker_name in missing_blockers:
        # Find the first test that has this blocker to get default values
        test_with_blocker = next((test for test in current_data if test.get('blocker') == blocker_name), None)
        if test_with_blocker:
            auto_create_blocker_if_needed(blocker_name, test_with_blocker)

def get_sharepoint_access_token():
    """Get access token for Microsoft Graph API"""
    try:
        # Check if credentials are configured
        if (SHAREPOINT_CONFIG['client_id'] == 'YOUR_CLIENT_ID_HERE' or 
            SHAREPOINT_CONFIG['client_secret'] == 'YOUR_CLIENT_SECRET_HERE' or 
            SHAREPOINT_CONFIG['tenant_id'] == 'YOUR_TENANT_ID_HERE'):
            return None, "SharePoint credentials not configured"
        
        # Create MSAL app
        app = msal.ConfidentialClientApplication(
            SHAREPOINT_CONFIG['client_id'],
            authority=f"https://login.microsoftonline.com/{SHAREPOINT_CONFIG['tenant_id']}",
            client_credential=SHAREPOINT_CONFIG['client_secret']
        )
        
        # Get token for Microsoft Graph
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        
        if "access_token" in result:
            return result["access_token"], None
        else:
            return None, f"Failed to acquire token: {result.get('error_description', 'Unknown error')}"
            
    except Exception as e:
        return None, f"Authentication error: {str(e)}"

def download_sharepoint_file():
    """Download Excel file from SharePoint using Microsoft Graph API"""
    try:
        # Get access token
        access_token, error = get_sharepoint_access_token()
        if error:
            return None, error
        
        # Extract site and file information from SharePoint URL
        # Parse the SharePoint URL to get the site and file path
        site_name = "DWT_TransformationDC-GLCLCs"
        file_path = SHAREPOINT_CONFIG['file_path']
        
        # Microsoft Graph API endpoint to get file content
        graph_url = f"https://graph.microsoft.com/v1.0/sites/corpdir.sharepoint.com:/sites/{site_name}:/drive/root:{file_path}:/content"
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        }
        
        response = requests.get(graph_url, headers=headers)
        
        if response.status_code == 200:
            return BytesIO(response.content), None
        else:
            return None, f"Failed to download file: HTTP {response.status_code} - {response.text}"
            
    except Exception as e:
        return None, f"Download error: {str(e)}"

def import_from_sharepoint():
    """Import data from SharePoint Excel file"""
    global current_data, current_blockers
    
    try:
        # Download file from SharePoint
        file_content, error = download_sharepoint_file()
        if error:
            return False, error
        
        # Read Excel file from memory
        df = pd.read_excel(file_content)
        
        # Process the data (replace existing data)
        processed_data = process_test_plan_data(df)
        current_data = processed_data
        
        # Reset blockers to ensure clean state
        current_blockers = []
        
        # Sync blockers from the new data
        sync_existing_blockers()
        
        return True, f"Successfully imported {len(processed_data)} tests from SharePoint"
        
    except Exception as e:
        return False, f"Import error: {str(e)}"

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        users = load_users()
        if username in users:
            user_data = users[username]
            if user_data.get('active', True) and bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash'].encode('utf-8')):
                user = User(username, user_data.get('role', 'viewer'), user_data.get('active', True))
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'error')
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/admin')
@role_required('admin')
def admin_panel():
    users = load_users()
    return render_template('admin.html', users=users)

@app.route('/admin/add_user', methods=['POST'])
@role_required('admin')
def add_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'viewer')
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password are required'}), 400
    
    users = load_users()
    if username in users:
        return jsonify({'success': False, 'error': 'User already exists'}), 400
    
    users[username] = {
        'password_hash': bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        'role': role,
        'active': True,
        'created_at': datetime.now().isoformat()
    }
    
    save_users(users)
    return jsonify({'success': True, 'message': 'User added successfully'})

@app.route('/admin/update_user', methods=['POST'])
@role_required('admin')
def update_user():
    data = request.get_json()
    username = data.get('username')
    role = data.get('role')
    active = data.get('active')
    new_password = data.get('new_password')
    
    users = load_users()
    if username not in users:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    if role:
        users[username]['role'] = role
    if active is not None:
        users[username]['active'] = active
    if new_password:
        users[username]['password_hash'] = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    save_users(users)
    return jsonify({'success': True, 'message': 'User updated successfully'})

@app.route('/admin/delete_user', methods=['POST'])
@role_required('admin')
def delete_user():
    data = request.get_json()
    username = data.get('username')
    
    if username == 'admin':
        return jsonify({'success': False, 'error': 'Cannot delete admin user'}), 400
    
    users = load_users()
    if username in users:
        del users[username]
        save_users(users)
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    
    return jsonify({'success': False, 'error': 'User not found'}), 404

@app.route('/')
@auth_required
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
@auth_required
@role_required('editor')
def upload_file():
    global current_data
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and file.filename.lower().endswith(('.xlsx', '.xls')):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Read Excel file
            df = pd.read_excel(filepath)
            
            # Process the data
            processed_data = process_test_plan_data(df)
            current_data = processed_data
            
            return jsonify({
                'success': True,
                'message': 'File uploaded and processed successfully',
                'data': processed_data
            })
        
        except Exception as e:
            return jsonify({'error': f'Error processing file: {str(e)}'}), 500
    
    return jsonify({'error': 'Invalid file format. Please upload an Excel file.'}), 400

def process_test_plan_data(df):
    """Process the Excel data into the required format"""
    processed_data = []
    
    # Expected columns: Test, Description, Status, Progress, Responsible, Location, Blocker, Start Date, Due Date
    for index, row in df.iterrows():
        # Parse start date and convert to DD.MM.YYYY format
        start_date = ''
        if pd.notna(row.get('Start Date')):
            try:
                if isinstance(row.get('Start Date'), str):
                    # Try to parse various date formats and convert to DD.MM.YYYY
                    from datetime import datetime
                    # Try DD/MM/YYYY format first
                    try:
                        parsed_date = datetime.strptime(row.get('Start Date'), '%d/%m/%Y')
                        start_date = parsed_date.strftime('%d.%m.%Y')
                    except:
                        # Try DD.MM.YYYY format
                        try:
                            parsed_date = datetime.strptime(row.get('Start Date'), '%d.%m.%Y')
                            start_date = parsed_date.strftime('%d.%m.%Y')
                        except:
                            # Try YYYY-MM-DD format
                            try:
                                parsed_date = datetime.strptime(row.get('Start Date'), '%Y-%m-%d')
                                start_date = parsed_date.strftime('%d.%m.%Y')
                            except:
                                start_date = str(row.get('Start Date', ''))
                else:
                    # Handle pandas datetime
                    start_date = row.get('Start Date').strftime('%d.%m.%Y')
            except:
                start_date = str(row.get('Start Date', ''))
        
        # Parse due date and convert to DD.MM.YYYY format
        due_date = ''
        if pd.notna(row.get('Due Date')):
            try:
                if isinstance(row.get('Due Date'), str):
                    # Try to parse various date formats and convert to DD.MM.YYYY
                    from datetime import datetime
                    # Try DD/MM/YYYY format first
                    try:
                        parsed_date = datetime.strptime(row.get('Due Date'), '%d/%m/%Y')
                        due_date = parsed_date.strftime('%d.%m.%Y')
                    except:
                        # Try DD.MM.YYYY format
                        try:
                            parsed_date = datetime.strptime(row.get('Due Date'), '%d.%m.%Y')
                            due_date = parsed_date.strftime('%d.%m.%Y')
                        except:
                            # Try YYYY-MM-DD format
                            try:
                                parsed_date = datetime.strptime(row.get('Due Date'), '%Y-%m-%d')
                                due_date = parsed_date.strftime('%d.%m.%Y')
                            except:
                                due_date = str(row.get('Due Date', ''))
                else:
                    # Handle pandas datetime
                    due_date = row.get('Due Date').strftime('%d.%m.%Y')
            except:
                due_date = str(row.get('Due Date', ''))
        
        test_item = {
            'id': index + 1,
            'test': str(row.get('Test', f'Test {index + 1}')),
            'description': str(row.get('Description', '')),
            'status': str(row.get('Status', 'open')).lower(),
            'progress': int(row.get('Progress', 0)) if pd.notna(row.get('Progress', 0)) else 0,
            'responsible': str(row.get('Responsible', '')),
            'location': str(row.get('Location', '')),
            'blocker': str(row.get('Blocker', '')) if row.get('Status', '').lower() == 'blocked' else '',
            'start_date': start_date,
            'due_date': due_date
        }
        
        # Auto-create blocker if blocker name is provided during import
        if test_item['blocker']:
            auto_create_blocker_if_needed(test_item['blocker'], test_item)
        
        processed_data.append(test_item)
    
    return processed_data

def process_prep_tasks_data(df):
    """Process the Excel preparation tasks data into the required format"""
    processed_data = []
    
    # Expected columns: Activity Title, Description, Due Date, Progress, Responsible, Location, Blocker, Volume, Status
    for index, row in df.iterrows():
        # Parse due date and convert to DD.MM.YYYY format for consistency
        due_date = ''
        if pd.notna(row.get('Due Date')):
            try:
                if isinstance(row.get('Due Date'), str):
                    # Try to parse various date formats and convert to DD.MM.YYYY
                    from datetime import datetime
                    # Try DD/MM/YYYY format first
                    try:
                        parsed_date = datetime.strptime(row.get('Due Date'), '%d/%m/%Y')
                        due_date = parsed_date.strftime('%d.%m.%Y')
                    except:
                        # Try DD.MM.YYYY format
                        try:
                            parsed_date = datetime.strptime(row.get('Due Date'), '%d.%m.%Y')
                            due_date = parsed_date.strftime('%d.%m.%Y')
                        except:
                            # Try YYYY-MM-DD format
                            try:
                                parsed_date = datetime.strptime(row.get('Due Date'), '%Y-%m-%d')
                                due_date = parsed_date.strftime('%d.%m.%Y')
                            except:
                                due_date = str(row.get('Due Date', ''))
                else:
                    # Handle pandas datetime
                    due_date = row.get('Due Date').strftime('%d.%m.%Y')
            except:
                due_date = str(row.get('Due Date', ''))
        
        prep_task = {
            'id': index + 1,
            'activity_title': str(row.get('Activity Title', f'Task {index + 1}')),
            'description': str(row.get('Description', '')),
            'due_date': due_date,
            'status': str(row.get('Status', 'not started')).lower().replace(' ', '_'),
            'progress': int(row.get('Progress', 0)) if pd.notna(row.get('Progress', 0)) else 0,
            'responsible': str(row.get('Responsible', '')),
            'location': str(row.get('Location', '')),
            'blocker': str(row.get('Blocker', '')) if str(row.get('Status', '')).lower() == 'blocked' else '',
            'volume': str(row.get('Volume', 'm')).lower()
        }
        
        # Auto-create blocker if blocker name is provided during import
        if prep_task['blocker']:
            auto_create_blocker_if_needed(prep_task['blocker'], {'test': prep_task['activity_title'], 'responsible': prep_task['responsible']})
        
        processed_data.append(prep_task)
    
    return processed_data

def import_prep_tasks_from_sharepoint():
    """Import preparation tasks from SharePoint Excel file"""
    global current_prep_tasks, current_blockers
    
    try:
        # Download file from SharePoint
        file_content, error = download_sharepoint_file()
        if error:
            return False, error
        
        # Read Excel file from memory, try to get 'Preparation Tasks' sheet
        try:
            df = pd.read_excel(file_content, sheet_name='Preparation Tasks')
        except:
            # If no 'Preparation Tasks' sheet, return error
            return False, "No 'Preparation Tasks' sheet found in Excel file"
        
        # Process the data (replace existing data)
        processed_data = process_prep_tasks_data(df)
        current_prep_tasks = processed_data
        
        # Sync blockers from the new data
        sync_existing_blockers()
        
        return True, f"Successfully imported {len(processed_data)} preparation tasks from SharePoint"
        
    except Exception as e:
        return False, f"Import error: {str(e)}"

@app.route('/api/data')
def get_data():
    global current_data
    
    # Auto-import from SharePoint if no data is available
    if current_data is None:
        success, message = import_from_sharepoint()
        if not success:
            # If SharePoint import fails, create sample data for testing
            print(f"SharePoint import failed: {message}")
            current_data = create_sample_test_data()
    
    return jsonify(current_data)

def create_sample_test_data():
    """Create sample test data with DD.MM.YYYY dates for testing"""
    from datetime import datetime, timedelta
    
    today = datetime.now()
    sample_data = [
        {
            'id': 1,
            'test': 'Connection Test',
            'description': 'Test telnet connection to server',
            'status': 'in_progress',
            'progress': 75,
            'responsible': 'John Doe',
            'location': 'Server Room A',
            'blocker': '',
            'start_date': (today - timedelta(days=5)).strftime('%d.%m.%Y'),
            'due_date': (today + timedelta(days=2)).strftime('%d.%m.%Y')
        },
        {
            'id': 2,
            'test': 'Authentication Test',
            'description': 'Verify user authentication works correctly',
            'status': 'completed',
            'progress': 100,
            'responsible': 'Jane Smith',
            'location': 'Lab B',
            'blocker': '',
            'start_date': (today - timedelta(days=10)).strftime('%d.%m.%Y'),
            'due_date': (today - timedelta(days=1)).strftime('%d.%m.%Y')
        },
        {
            'id': 3,
            'test': 'Performance Test',
            'description': 'Test system performance under load',
            'status': 'blocked',
            'progress': 30,
            'responsible': 'Mike Johnson',
            'location': 'Data Center',
            'blocker': 'Hardware Issue',
            'start_date': (today - timedelta(days=3)).strftime('%d.%m.%Y'),
            'due_date': (today + timedelta(days=7)).strftime('%d.%m.%Y')
        },
        {
            'id': 4,
            'test': 'Security Test',
            'description': 'Verify security protocols are working',
            'status': 'open',
            'progress': 0,
            'responsible': 'Sarah Wilson',
            'location': 'Security Lab',
            'blocker': '',
            'start_date': (today + timedelta(days=1)).strftime('%d.%m.%Y'),
            'due_date': (today + timedelta(days=14)).strftime('%d.%m.%Y')
        }
    ]
    
    return sample_data

@app.route('/api/import_sharepoint', methods=['POST'])
@auth_required
@role_required('editor')
def import_sharepoint_data():
    """Manual endpoint to import data from SharePoint"""
    success, message = import_from_sharepoint()
    
    if success:
        return jsonify({'success': True, 'message': message, 'data': current_data})
    else:
        return jsonify({'success': False, 'error': message}), 500

@app.route('/api/update_status', methods=['POST'])
@auth_required
@role_required('editor')
def update_status():
    global current_data, current_blockers
    
    data = request.get_json()
    test_id = data.get('id')
    new_status = data.get('status')
    new_progress = data.get('progress', 0)
    blocker_info = data.get('blocker', '')
    
    if current_data:
        for item in current_data:
            if item['id'] == test_id:
                old_blocker = item.get('blocker', '')
                old_status = item.get('status', '')
                
                item['status'] = new_status
                item['progress'] = new_progress
                item['blocker'] = blocker_info if new_status == 'blocked' else ''
                
                # Auto-create blocker if status changed to blocked and blocker info provided
                if new_status == 'blocked' and blocker_info and blocker_info != old_blocker:
                    auto_create_blocker_if_needed(blocker_info, item)
                
                # Cleanup logic: if status changed from blocked to something else, check if blocker is still needed
                if old_status == 'blocked' and new_status != 'blocked' and old_blocker:
                    cleanup_unused_blocker(old_blocker)
                
                break
        
        return jsonify({'success': True, 'message': 'Status updated successfully'})
    
    return jsonify({'error': 'No data available'}), 404

@app.route('/api/update_test', methods=['POST'])
@auth_required
@role_required('editor')
def update_test():
    global current_data, current_blockers
    
    data = request.get_json()
    test_id = data.get('id')
    
    if current_data:
        for item in current_data:
            if item['id'] == test_id:
                old_blocker = item.get('blocker', '')
                new_blocker = data.get('blocker', '')
                
                item['test'] = data.get('test', item['test'])
                item['description'] = data.get('description', item['description'])
                item['responsible'] = data.get('responsible', item['responsible'])
                item['location'] = data.get('location', item['location'])
                item['status'] = data.get('status', item['status'])
                item['progress'] = data.get('progress', item['progress'])
                item['blocker'] = new_blocker
                item['start_date'] = data.get('start_date', item.get('start_date', ''))
                item['due_date'] = data.get('due_date', item.get('due_date', ''))
                
                # Auto-create blocker if new blocker name is provided and doesn't exist
                if new_blocker and new_blocker != old_blocker:
                    auto_create_blocker_if_needed(new_blocker, item)
                
                break
        
        return jsonify({'success': True, 'message': 'Test updated successfully'})
    
    return jsonify({'error': 'No data available'}), 404

@app.route('/api/add_test', methods=['POST'])
@auth_required
@role_required('editor')
def add_test():
    global current_data, current_blockers
    
    data = request.get_json()
    
    if current_data is None:
        current_data = []
    
    # Get the next ID
    next_id = max([item['id'] for item in current_data], default=0) + 1
    
    new_test = {
        'id': next_id,
        'test': data.get('test', ''),
        'description': data.get('description', ''),
        'status': data.get('status', 'open'),
        'progress': data.get('progress', 0),
        'responsible': data.get('responsible', ''),
        'location': data.get('location', ''),
        'blocker': data.get('blocker', ''),
        'start_date': data.get('start_date', ''),
        'due_date': data.get('due_date', '')
    }
    
    # Auto-create blocker if blocker name is provided
    if new_test['blocker']:
        auto_create_blocker_if_needed(new_test['blocker'], new_test)
    
    current_data.append(new_test)
    
    return jsonify({'success': True, 'message': 'Test added successfully', 'test': new_test})

@app.route('/api/delete_test', methods=['POST'])
@auth_required
@role_required('editor')
def delete_test():
    global current_data
    
    data = request.get_json()
    test_id = data.get('id')
    
    if current_data:
        current_data = [item for item in current_data if item['id'] != test_id]
        return jsonify({'success': True, 'message': 'Test deleted successfully'})
    
    return jsonify({'error': 'No data available'}), 404

@app.route('/api/export')
def export_excel():
    global current_data, current_blockers, current_prep_tasks
    
    if not current_data and not current_blockers and not current_prep_tasks:
        return jsonify({'error': 'No data available to export'}), 404
    
    try:
        # Create export filename with timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'complete_export_{timestamp}.xlsx'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Create Excel writer object
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            
            # Export test plan data if available
            if current_data:
                df_tests = pd.DataFrame(current_data)
                # Reorder columns to match expected format
                df_tests = df_tests[['test', 'description', 'status', 'progress', 'responsible', 'location', 'blocker', 'start_date', 'due_date']]
                # Rename columns to match Excel format
                df_tests.columns = ['Test', 'Description', 'Status', 'Progress', 'Responsible', 'Location', 'Blocker', 'Start Date', 'Due Date']
                df_tests.to_excel(writer, sheet_name='Test Plan', index=False)
            
            # Export blocker data if available
            if current_blockers:
                df_blockers = pd.DataFrame(current_blockers)
                # Reorder columns to match expected format
                df_blockers = df_blockers[['name', 'description', 'responsible', 'start_date', 'priority', 'resolution_status']]
                # Rename columns to match Excel format
                df_blockers.columns = ['Blocker Name', 'Description', 'Responsible', 'Start Date', 'Priority', 'Resolution Status']
                df_blockers.to_excel(writer, sheet_name='Blockers', index=False)
            
            # Export preparation tasks data if available
            if current_prep_tasks:
                df_prep_tasks = pd.DataFrame(current_prep_tasks)
                # Reorder columns to match expected format
                df_prep_tasks = df_prep_tasks[['activity_title', 'description', 'due_date', 'status', 'progress', 'responsible', 'location', 'blocker', 'volume']]
                # Rename columns to match Excel format
                df_prep_tasks.columns = ['Activity Title', 'Description', 'Due Date', 'Status', 'Progress', 'Responsible', 'Location', 'Blocker', 'Volume']
                df_prep_tasks.to_excel(writer, sheet_name='Preparation Tasks', index=False)
        
        # Count exported items for message
        export_counts = []
        if current_data:
            export_counts.append(f"{len(current_data)} tests")
        if current_blockers:
            export_counts.append(f"{len(current_blockers)} blockers")
        if current_prep_tasks:
            export_counts.append(f"{len(current_prep_tasks)} preparation tasks")
        
        export_message = f"Export completed successfully with {', '.join(export_counts)}"
        
        return jsonify({
            'success': True, 
            'message': export_message,
            'filename': filename,
            'download_url': f'/download/{filename}'
        })
        
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_file(
            os.path.join(app.config['UPLOAD_FOLDER'], filename),
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'error': f'Download failed: {str(e)}'}), 404

@app.route('/dashboard')
@auth_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/blockers')
@auth_required
def blockers():
    return render_template('blockers.html')

# Blocker API endpoints
@app.route('/api/blockers')
def get_blockers():
    global current_blockers, current_data
    
    # Sync existing blockers from tests before returning data
    sync_existing_blockers()
    
    # Add affected tests information to each blocker
    blockers_with_tests = []
    for blocker in current_blockers:
        blocker_copy = blocker.copy()
        blocker_copy['affected_tests'] = get_affected_tests(blocker['name'])
        blockers_with_tests.append(blocker_copy)
    
    return jsonify(blockers_with_tests)

@app.route('/api/add_blocker', methods=['POST'])
@auth_required
@role_required('editor')
def add_blocker():
    global current_blockers
    
    data = request.get_json()
    
    # Get the next ID
    next_id = max([item['id'] for item in current_blockers], default=0) + 1
    
    new_blocker = {
        'id': next_id,
        'name': data.get('name', ''),
        'description': data.get('description', ''),
        'responsible': data.get('responsible', ''),
        'start_date': data.get('start_date', ''),
        'priority': data.get('priority', 'medium'),
        'resolution_status': data.get('resolution_status', 'open')
    }
    
    current_blockers.append(new_blocker)
    
    return jsonify({'success': True, 'message': 'Blocker added successfully', 'blocker': new_blocker})

@app.route('/api/update_blocker', methods=['POST'])
@auth_required
@role_required('editor')
def update_blocker():
    global current_blockers, current_data
    
    data = request.get_json()
    blocker_id = data.get('id')
    
    for item in current_blockers:
        if item['id'] == blocker_id:
            old_name = item['name']
            new_name = data.get('name', item['name'])
            
            item['name'] = new_name
            item['description'] = data.get('description', item['description'])
            item['responsible'] = data.get('responsible', item['responsible'])
            item['start_date'] = data.get('start_date', item['start_date'])
            item['priority'] = data.get('priority', item['priority'])
            item['resolution_status'] = data.get('resolution_status', item['resolution_status'])
            
            # Bidirectional update: if blocker name changed, update all related tests
            if old_name != new_name and current_data:
                for test in current_data:
                    if test['blocker'] == old_name:
                        test['blocker'] = new_name
            
            break
    
    return jsonify({'success': True, 'message': 'Blocker updated successfully'})

@app.route('/api/delete_blocker', methods=['POST'])
@auth_required
@role_required('editor')
def delete_blocker():
    global current_blockers
    
    data = request.get_json()
    blocker_id = data.get('id')
    
    current_blockers = [item for item in current_blockers if item['id'] != blocker_id]
    return jsonify({'success': True, 'message': 'Blocker deleted successfully'})

# Preparation Tasks API endpoints
@app.route('/prep_tasks')
@auth_required
def prep_tasks():
    return render_template('prep_tasks.html')

@app.route('/prep-tasks')
@auth_required
def prep_tasks_alt():
    return render_template('prep_tasks.html')

@app.route('/api/prep_tasks')
def get_prep_tasks():
    global current_prep_tasks
    
    # Auto-import from SharePoint if no data is available
    if not current_prep_tasks:
        success, message = import_prep_tasks_from_sharepoint()
        if not success:
            # If SharePoint import fails, create sample prep tasks for testing
            print(f"SharePoint prep tasks import failed: {message}")
            current_prep_tasks = create_sample_prep_tasks_data()
    
    # Ensure we always have valid preparation tasks data
    # If current_prep_tasks contains test plan data (has 'test' field instead of 'activity_title'), reset to sample data
    if current_prep_tasks and len(current_prep_tasks) > 0:
        first_task = current_prep_tasks[0]
        if 'test' in first_task and 'activity_title' not in first_task:
            print("DEBUG: Detected test plan data in prep_tasks, resetting to sample prep tasks data")
            current_prep_tasks = create_sample_prep_tasks_data()
    
    # Debug logging to verify we're returning the right data
    print(f"DEBUG: Returning {len(current_prep_tasks)} prep tasks")
    if current_prep_tasks:
        print(f"DEBUG: First prep task activity_title: {current_prep_tasks[0].get('activity_title', 'NO ACTIVITY_TITLE')}")
    
    return jsonify(current_prep_tasks)

def create_sample_prep_tasks_data():
    """Create sample prep tasks data with DD.MM.YYYY dates for testing"""
    from datetime import datetime, timedelta
    
    today = datetime.now()
    sample_data = [
        {
            'id': 1,
            'activity_title': 'Environment Setup',
            'description': 'Set up test environment for telnet testing',
            'start_date': (today - timedelta(days=2)).strftime('%d.%m.%Y'),
            'due_date': (today + timedelta(days=3)).strftime('%d.%m.%Y'),
            'status': 'in_progress',
            'progress': 60,
            'responsible': 'John Doe',
            'location': 'Server Room A',
            'blocker': '',
            'volume': 'l',
            'dependencies': []
        },
        {
            'id': 2,
            'activity_title': 'Network Configuration',
            'description': 'Configure network settings for testing',
            'start_date': (today + timedelta(days=4)).strftime('%d.%m.%Y'),
            'due_date': (today + timedelta(days=8)).strftime('%d.%m.%Y'),
            'status': 'not_started',
            'progress': 0,
            'responsible': 'Jane Smith',
            'location': 'Network Lab',
            'blocker': '',
            'volume': 'm',
            'dependencies': [1]
        },
        {
            'id': 3,
            'activity_title': 'Security Review',
            'description': 'Review security protocols before testing',
            'start_date': (today - timedelta(days=1)).strftime('%d.%m.%Y'),
            'due_date': (today + timedelta(days=2)).strftime('%d.%m.%Y'),
            'status': 'blocked',
            'progress': 25,
            'responsible': 'Mike Johnson',
            'location': 'Security Office',
            'blocker': 'Waiting for approval',
            'volume': 's',
            'dependencies': []
        },
        {
            'id': 4,
            'activity_title': 'Documentation Update',
            'description': 'Update test documentation',
            'start_date': (today - timedelta(days=3)).strftime('%d.%m.%Y'),
            'due_date': (today - timedelta(days=1)).strftime('%d.%m.%Y'),
            'status': 'completed',
            'progress': 100,
            'responsible': 'Sarah Wilson',
            'location': 'Office',
            'blocker': '',
            'volume': 'xs',
            'dependencies': []
        },
        {
            'id': 5,
            'activity_title': 'Hardware Check',
            'description': 'Verify all hardware is ready for testing',
            'start_date': (today + timedelta(days=5)).strftime('%d.%m.%Y'),
            'due_date': (today + timedelta(days=10)).strftime('%d.%m.%Y'),
            'status': 'not_started',
            'progress': 0,
            'responsible': 'Tom Brown',
            'location': 'Data Center',
            'blocker': '',
            'volume': 'xl',
            'dependencies': [2]
        },
        {
            'id': 6,
            'activity_title': 'Application Testing',
            'description': 'Test application functionality',
            'start_date': (today + timedelta(days=9)).strftime('%d.%m.%Y'),
            'due_date': (today + timedelta(days=15)).strftime('%d.%m.%Y'),
            'status': 'not_started',
            'progress': 0,
            'responsible': 'Alice Cooper',
            'location': 'Test Lab',
            'blocker': '',
            'volume': 'l',
            'dependencies': [1, 2, 3]
        }
    ]
    
    return sample_data

@app.route('/api/import_prep_tasks_sharepoint', methods=['POST'])
@auth_required
@role_required('editor')
def import_prep_tasks_sharepoint_endpoint():
    """Manual endpoint to import preparation tasks from SharePoint"""
    success, message = import_prep_tasks_from_sharepoint()
    
    if success:
        return jsonify({'success': True, 'message': message, 'data': current_prep_tasks})
    else:
        return jsonify({'success': False, 'error': message}), 500

@app.route('/api/upload_prep_tasks', methods=['POST'])
@auth_required
@role_required('editor')
def upload_prep_tasks_file():
    global current_prep_tasks
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and file.filename.lower().endswith(('.xlsx', '.xls')):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Read Excel file, try to get 'Preparation Tasks' sheet first
            try:
                df = pd.read_excel(filepath, sheet_name='Preparation Tasks')
            except:
                # If no 'Preparation Tasks' sheet, try the first sheet
                df = pd.read_excel(filepath)
            
            # Process the data
            processed_data = process_prep_tasks_data(df)
            current_prep_tasks = processed_data
            
            # Sync blockers from the new data
            sync_existing_blockers()
            
            return jsonify({
                'success': True,
                'message': 'Preparation tasks file uploaded and processed successfully',
                'data': processed_data
            })
        
        except Exception as e:
            return jsonify({'error': f'Error processing file: {str(e)}'}), 500
    
    return jsonify({'error': 'Invalid file format. Please upload an Excel file.'}), 400

@app.route('/api/add_prep_task', methods=['POST'])
@auth_required
@role_required('editor')
def add_prep_task():
    global current_prep_tasks, current_blockers
    
    data = request.get_json()
    
    if current_prep_tasks is None:
        current_prep_tasks = []
    
    # Get the next ID
    next_id = max([item['id'] for item in current_prep_tasks], default=0) + 1
    
    new_prep_task = {
        'id': next_id,
        'activity_title': data.get('activity_title', ''),
        'description': data.get('description', ''),
        'start_date': data.get('start_date', ''),
        'due_date': data.get('due_date', ''),
        'status': data.get('status', 'not_started'),
        'progress': data.get('progress', 0),
        'responsible': data.get('responsible', ''),
        'location': data.get('location', ''),
        'blocker': data.get('blocker', ''),
        'volume': data.get('volume', 'm')
    }
    
    # Auto-create blocker if blocker name is provided
    if new_prep_task['blocker']:
        auto_create_blocker_if_needed(new_prep_task['blocker'], {'test': new_prep_task['activity_title'], 'responsible': new_prep_task['responsible']})
    
    current_prep_tasks.append(new_prep_task)
    
    return jsonify({'success': True, 'message': 'Preparation task added successfully', 'prep_task': new_prep_task})

@app.route('/api/update_prep_task', methods=['POST'])
@auth_required
@role_required('editor')
def update_prep_task():
    global current_prep_tasks, current_blockers
    
    data = request.get_json()
    prep_task_id = data.get('id')
    
    if current_prep_tasks:
        for item in current_prep_tasks:
            if item['id'] == prep_task_id:
                old_blocker = item.get('blocker', '')
                new_blocker = data.get('blocker', '')
                
                item['activity_title'] = data.get('activity_title', item['activity_title'])
                item['description'] = data.get('description', item['description'])
                item['start_date'] = data.get('start_date', item.get('start_date', ''))
                item['due_date'] = data.get('due_date', item['due_date'])
                item['status'] = data.get('status', item['status'])
                item['progress'] = data.get('progress', item['progress'])
                item['responsible'] = data.get('responsible', item['responsible'])
                item['location'] = data.get('location', item.get('location', ''))
                item['blocker'] = new_blocker
                item['volume'] = data.get('volume', item['volume'])
                
                # Auto-create blocker if new blocker name is provided and doesn't exist
                if new_blocker and new_blocker != old_blocker:
                    auto_create_blocker_if_needed(new_blocker, {'test': item['activity_title'], 'responsible': item['responsible']})
                
                break
        
        return jsonify({'success': True, 'message': 'Preparation task updated successfully'})
    
    return jsonify({'error': 'No data available'}), 404

@app.route('/api/update_prep_task_status', methods=['POST'])
@auth_required
@role_required('editor')
def update_prep_task_status():
    global current_prep_tasks, current_blockers
    
    data = request.get_json()
    prep_task_id = data.get('id')
    new_status = data.get('status')
    new_progress = data.get('progress', 0)
    blocker_info = data.get('blocker', '')
    
    if current_prep_tasks:
        for item in current_prep_tasks:
            if item['id'] == prep_task_id:
                old_blocker = item.get('blocker', '')
                old_status = item.get('status', '')
                
                item['status'] = new_status
                item['progress'] = new_progress
                item['blocker'] = blocker_info if new_status == 'blocked' else ''
                
                # Auto-create blocker if status changed to blocked and blocker info provided
                if new_status == 'blocked' and blocker_info and blocker_info != old_blocker:
                    auto_create_blocker_if_needed(blocker_info, {'test': item['activity_title'], 'responsible': item['responsible']})
                
                # Cleanup logic: if status changed from blocked to something else, check if blocker is still needed
                if old_status == 'blocked' and new_status != 'blocked' and old_blocker:
                    cleanup_unused_blocker(old_blocker)
                
                break
        
        return jsonify({'success': True, 'message': 'Preparation task status updated successfully'})
    
    return jsonify({'error': 'No data available'}), 404

@app.route('/api/delete_prep_task', methods=['POST'])
@auth_required
@role_required('editor')
def delete_prep_task():
    global current_prep_tasks
    
    data = request.get_json()
    prep_task_id = data.get('id')
    
    if current_prep_tasks:
        current_prep_tasks = [item for item in current_prep_tasks if item['id'] != prep_task_id]
        return jsonify({'success': True, 'message': 'Preparation task deleted successfully'})
    
    return jsonify({'error': 'No data available'}), 404

if __name__ == '__main__':
    import os
    # Get port from environment variable (for cloud deployment) or default to 5000
    port = int(os.environ.get('PORT', 5000))
    # Get debug mode from environment variable or default to True for local development
    debug_mode = os.environ.get('FLASK_ENV', 'development') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
