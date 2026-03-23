# Cloud Log Analytics - Secure Flask Application

A secure, privacy-focused Flask web application for analyzing AWS CloudWatch logs with minimal dependencies and strong security measures.

## Features

✅ **Security-First Design**
- AWS credentials stored ONLY in encrypted session memory (never logged or persisted to disk)
- CSRF protection on all forms
- Security headers on all responses
- Rate limiting to prevent brute force attacks
- Input validation and sanitization
- User consent required before credential submission

✅ **Core Functionality**
- Upload and analyze AWS CloudWatch logs
- Secure S3 file uploads with metadata
- Log analysis and results dashboard
- User authentication and session management
- Privacy-focused design with automatic session cleanup

## Project Structure

```
CloudLogProject/
├── app.py                  # Main Flask application
├── aws_utils.py           # AWS boto3 utilities
├── uploader.py            # File upload handlers
├── requirements.txt       # Python dependencies
├── static/                # CSS and static assets
│   └── style.css
├── templates/             # HTML templates
│   ├── dashboard.html
│   ├── login.html
│   ├── results.html
│   └── ...
├── logs/                  # Application logs directory
└── Cloudlogprojects/      # User project data
```

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/JhothiPrakash/CloudLogProject.git
cd CloudLogProject
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure AWS (Optional)
The application uses session-based AWS credentials. You can provide credentials through the web interface when needed.

### 5. Run the Application
```bash
python app.py
```

The application will start on `http://localhost:5000`

## Usage

1. **Login**: Access the login page at `/login`
2. **Submit AWS Credentials**: Provide your AWS access key, secret key, and region
3. **Upload Logs**: Upload CloudWatch logs files for analysis
4. **View Results**: Access your analysis results on the dashboard

## Security Warnings ⚠️

- **Never share AWS credentials** in code or version control
- **Use IAM roles** when running on AWS infrastructure
- **Rotate credentials** regularly
- **Use HTTPS** in production environments
- **Enable rate limiting** in production
- **Set strong passwords** for user accounts

## Configuration

### S3 Bucket Name
Edit `app.py` and update:
```python
S3_BUCKET_NAME = "your-s3-bucket-name"  # Configure this
```

### DynamoDB Table (Optional)
```python
DYNAMODB_TABLE = "your-dynamodb-table"
```

## Dependencies

- Flask >= 2.3.0 - Web framework
- boto3 >= 1.28.0 - AWS SDK for Python

See `requirements.txt` for complete list.

## Troubleshooting

### ModuleNotFoundError
Make sure your virtual environment is activated and dependencies are installed:
```bash
pip install -r requirements.txt
```

### AWS Credential Errors
1. Verify your AWS credentials are correct
2. Check that your IAM user has appropriate S3 permissions
3. Ensure the S3 bucket name is configured in `app.py`

### Port Already in Use
If port 5000 is in use, modify the port in `app.py`:
```python
app.run(debug=True, port=5001)
```

## Privacy & Data Handling

- User sessions are cleared on logout
- AWS credentials are never persisted to disk
- All uploads are secured with metadata
- Access is user-specific and isolated

## License

This project is provided as-is for educational and professional use.

## Support

For issues or questions, please check the application logs in the `logs/` directory.

---

**Last Updated**: March 2026
