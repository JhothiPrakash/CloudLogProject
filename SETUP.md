# Setup Instructions - Cloud Log Analytics

## Step-by-Step Setup Guide

### Prerequisites Check
Ensure you have the following installed:
- Python 3.8+ (`python --version`)
- pip (`pip --version`)
- Git (`git --version`)

## Installation Steps

### 1. Clone Repository
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
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Expected output shows Flask and boto3 installed.

### 4. AWS Configuration

#### Get Your AWS Credentials
1. Log in to AWS Console
2. Go to IAM > Users > Your User > Security Credentials
3. Create Access Key if needed
4. Note your:
   - Access Key ID
   - Secret Access Key
   - Preferred Region (e.g., us-east-1)

#### Create S3 Bucket (if needed)
```bash
# Using AWS CLI (if installed)
aws s3 mb s3://your-unique-bucket-name --region us-east-1
```

#### Update app.py
Edit line 48-49 in `app.py`:
```python
S3_BUCKET_NAME = "your-actual-s3-bucket-name"
DYNAMODB_TABLE = ""  # Leave empty if not using DynamoDB
```

### 5. Run the Application
```bash
python app.py
```

You should see output like:
```
 * Serving Flask app 'app'
 * Debug mode: off
 * Running on http://127.0.0.1:5000
```

### 6. Access the Application
Open browser and go to: `http://localhost:5000`

### 7. First Time Login
- Enter your AWS credentials on the login page
- Select your region
- Click "Login & Store Credentials"

Credentials will be stored only in encrypted session memory.

## Verification Checklist

- [ ] Python 3.8+ installed
- [ ] Virtual environment activated
- [ ] All requirements installed (`pip list` shows flask and boto3)
- [ ] AWS credentials obtained
- [ ] S3 bucket name configured in app.py
- [ ] Application runs without errors
- [ ] Can access localhost:5000
- [ ] Can log in with AWS credentials

## Common Issues & Solutions

### Issue: Module not found error
**Solution**: Make sure virtual environment is activated
```bash
# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### Issue: AWS credentials invalid
**Solution**: 
- Double-check Access Key ID and Secret Key
- Verify credentials in AWS Console
- Check IAM user has S3 permissions

### Issue: Port 5000 in use
**Solution**: Change port in app.py or kill process using the port
```python
app.run(host='localhost', port=5001)  # Use different port
```

### Issue: SSL Certificate Error
**Solution**: This is expected in development. The app works over HTTP.

## Next Steps

1. Upload your first log file
2. Review the analysis results
3. Check the history page
4. Explore the dashboard features

## Production Deployment

For deploying to production:
1. Set `FLASK_ENV=production`
2. Set strong `FLASK_SECRET_KEY` environment variable
3. Use HTTPS with SSL certificate
4. Deploy behind reverse proxy (nginx, Apache)
5. Use environment variables for sensitive configs
6. Enable security headers in production mode

---

**Need Help?** Check README.md for detailed documentation and troubleshooting.
