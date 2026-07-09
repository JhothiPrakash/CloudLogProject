# Cloud Log Analytics

A secure Flask web application for analyzing cloud logs with AWS integration. This application allows users to securely upload and analyze log files stored in AWS S3 with integrated analytics and reporting.

## 🔒 Security Features

- **AWS Credentials Protection**: Credentials stored only in encrypted session memory, never logged or persisted
- **CSRF Protection**: Cross-Site Request Forgery protection on all forms
- **Security Headers**: Comprehensive security headers on all HTTP responses
- **Rate Limiting**: Protection against brute force attacks
- **Session Management**: Automatic session timeout after 30 minutes of inactivity
- **Input Validation**: All user inputs are validated and sanitized
- **User Isolation**: Users can only access their own uploaded results
- **File Upload Restrictions**: Limited file types (.log, .txt) and max size (50MB)

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- AWS Account with S3 and DynamoDB access
- Git (for version control)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/JhothiPrakash/CloudLogProject.git
cd CloudLogProject
```

### 2. Create a Virtual Environment

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure AWS Credentials

The application accepts AWS credentials through the web interface. **Do not store credentials in files or environment variables for security reasons.**

**Option A: Use AWS Credentials in Web Interface (Recommended)**
- Start the application and enter your AWS credentials through the login page
- Credentials are stored only in encrypted session memory

**Option B: Set Environment Variables (Development Only)**
```bash
# Windows
set AWS_ACCESS_KEY_ID=your_access_key
set AWS_SECRET_ACCESS_KEY=your_secret_key
set AWS_DEFAULT_REGION=us-east-1

# macOS/Linux
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

### 5. Configure Application Settings

Edit `app.py` and update these settings:

```python
S3_BUCKET_NAME = "your-s3-bucket-name"  # Your S3 bucket name
DYNAMODB_TABLE = "your-table-name"       # Your DynamoDB table name (optional)
```

### 6. Run the Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

## 📁 Project Structure

```
CloudLogProject/
├── app.py                 # Main Flask application
├── aws_utils.py          # AWS S3 and credential utilities
├── uploader.py           # File upload handling
├── requirements.txt      # Python dependencies
├── README.md             # This file
├── templates/            # HTML templates
│   ├── login.html
│   ├── dashboard.html
│   ├── results.html
│   ├── history.html
│   ├── error.html
│   └── privacy.html
├── static/              # Static files
│   └── style.css
└── logs/                # Application logs directory
```

## 🔑 Key Features

### User Authentication
- Secure login system with session management
- Automatic session timeout for security
- User consent before credential submission

### Log Upload and Analysis
- Support for `.log` and `.txt` file formats
- Max file size: 50MB
- Automatic log analysis and insights
- Results stored in user-specific sessions

### Dashboard
- View upload history
- Access analysis results
- Download processed logs
- View privacy information

## ⚙️ Configuration Options

Edit `app.py` to customize:

| Setting | Default | Purpose |
|---------|---------|---------|
| `MAX_CONTENT_LENGTH` | 50MB | Maximum file upload size |
| `SESSION_TIMEOUT` | 1800s | Session expiration time |
| `RATE_LIMIT_WINDOW` | 300s | Rate limiting window |
| `MAX_LOGIN_ATTEMPTS` | 5 | Failed login attempts before lockout |
| `MAX_UPLOAD_ATTEMPTS` | 20 | Upload rate limit |

## 🛡️ Environment Variables (Optional)

```bash
FLASK_SECRET_KEY       # Flask session encryption key (auto-generated if not set)
FLASK_ENV             # Set to 'production' for production deployment
AWS_REGION            # Default AWS region
```

## 📝 Usage Example

1. **Login**: Navigate to `http://localhost:5000` and login with your AWS credentials
2. **Upload Log**: Click "Upload Log File" and select a `.log` or `.txt` file
3. **View Results**: Browse analysis results in the dashboard
4. **Download**: Download processed logs if available
5. **Logout**: Click logout to clear all session data

## 🧪 Testing

To test credential validation:
```python
python -c "from aws_utils import validate_aws_credentials; \
validate_aws_credentials('YOUR_KEY', 'YOUR_SECRET', 'us-east-1')"
```

## 📚 API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Dashboard (redirects to login if not authenticated) |
| `/login` | GET, POST | User login page |
| `/logout` | GET | Clear session and logout |
| `/upload` | POST | Upload log file |
| `/results` | GET | View analysis results |
| `/history` | GET | View upload history |
| `/privacy` | GET | Privacy information |

## 🚨 Security Notes

### Development vs Production

**Development:**
- Uses `SESSION_COOKIE_SECURE=False` (works over HTTP)
- Auto-generated secret key

**Production:**
- Set `SESSION_COOKIE_SECURE=True` (HTTPS only)
- Set strong `FLASK_SECRET_KEY` environment variable
- Deploy behind HTTPS reverse proxy
- Disable debug mode
- Use environment variables for sensitive configs

### Credentials Best Practices

✅ **DO:**
- Use the web interface to enter credentials
- Rotate AWS access keys regularly
- Use IAM roles with minimal permissions
- Enable MFA on AWS account
- Use temporary security credentials when possible

❌ **DON'T:**
- Store credentials in source code
- Commit `.env` files with credentials
- Log or print credentials
- Share credentials via insecure channels

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Windows
netstat -ano | findstr :5000

# macOS/Linux
lsof -i :5000
```

### AWS Credentials Invalid
- Verify credentials in AWS Console
- Check IAM user permissions (S3, DynamoDB)
- Ensure credentials haven't expired

### File Upload Failed
- Check file format (.log or .txt only)
- Verify file size < 50MB
- Check S3 bucket permissions

### Session Expired
- Log in again
- Session times out after 30 minutes of inactivity
- Credentials are cleared on logout

## 📄 License

This project is provided as-is for educational and business purposes.

## 📧 Support

For issues or questions, please open an issue on GitHub or contact the project maintainer.

## 🔄 Version History

- **v1.0** - Initial release with secure credential handling and log analysis

---

**Last Updated**: March 2026

Made with ❤️ by Jothi Prakash
