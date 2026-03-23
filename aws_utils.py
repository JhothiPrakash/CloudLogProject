

import time
import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError


def get_boto3_client(service_name: str, session: dict):
    """
    Create a boto3 client using credentials from Flask session.
    Credentials are NEVER logged or stored.
    """
    access_key = session.get('aws_access_key')
    secret_key = session.get('aws_secret_key')
    region = session.get('aws_region')
    
    if not all([access_key, secret_key, region]):
        raise ValueError("AWS credentials not found in session")
    
    return boto3.client(
        service_name,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )


def validate_aws_credentials(access_key: str, secret_key: str, region: str) -> tuple:
    """
    Validate AWS credentials using STS GetCallerIdentity.
    Returns generic error messages to prevent enumeration attacks.
    """
    try:
        sts_client = boto3.client(
            'sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        
        response = sts_client.get_caller_identity()
        account_id = response.get('Account', 'Unknown')
        # Mask account ID for security
        masked_account = account_id[:4] + '****' + account_id[-2:] if len(account_id) >= 6 else '****'
        return True, f"Connected (Account: {masked_account})"
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        
        if error_code in ['InvalidClientTokenId', 'SignatureDoesNotMatch', 'AccessDenied']:
            return False, "Invalid credentials"
        else:
            return False, "Authentication failed"
            
    except NoCredentialsError:
        return False, "Credentials required"
        
    except BotoCoreError:
        return False, "Connection error"
        
    except Exception:
        return False, "Authentication error"


def upload_file_to_s3(
    session: dict,
    file_content: bytes,
    bucket_name: str,
    s3_key: str,
    file_hash: str,
    log_type: str
) -> tuple:
    """
    Upload file to S3 with metadata.
    Does NOT log any credential information.
    """
    try:
        s3_client = get_boto3_client('s3', session)
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=file_content,
            ContentType='application/gzip',
            ContentEncoding='gzip',
            Metadata={
                'sha256': file_hash,
                'log-type': log_type,
                'source': 'secure-flask-app'
            }
        )
        
        return True, "Upload successful"
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        
        if error_code == 'NoSuchBucket':
            return False, "Storage not configured"
        elif error_code == 'AccessDenied':
            return False, "Access denied"
        else:
            return False, "Upload failed"
            
    except ValueError as e:
        return False, str(e)
        
    except Exception:
        return False, "Upload error"


def get_analysis_results(
    session: dict,
    table_name: str,
    filename: str,
    max_retries: int = 5,
    retry_delay: float = 2.0
) -> tuple:
    """
    Fetch analysis results from DynamoDB.
    Only returns data for the specified filename.
    """
    try:
        dynamodb = get_boto3_client('dynamodb', session)
        
        for attempt in range(max_retries):
            try:
                response = dynamodb.get_item(
                    TableName=table_name,
                    Key={
                        'filename': {'S': filename}
                    }
                )
                
                if 'Item' in response:
                    item = response['Item']
                    
                    results = {
                        'filename': item.get('filename', {}).get('S', filename),
                        'errors': int(item.get('errors', {}).get('N', 0)),
                        'warnings': int(item.get('warnings', {}).get('N', 0)),
                        'unique_ips': int(item.get('unique_ips', {}).get('N', 0)),
                        'most_frequent_ip': item.get('most_frequent_ip', {}).get('S', 'N/A'),
                        'total_lines': int(item.get('total_lines', {}).get('N', 0)),
                        'timestamp': item.get('timestamp', {}).get('S', 'N/A'),
                        'log_type': item.get('log_type', {}).get('S', 'Unknown')
                    }
                    
                    if 'ip_list' in item:
                        ip_list = item['ip_list'].get('L', [])
                        results['ip_list'] = [ip.get('S', '') for ip in ip_list]
                    else:
                        results['ip_list'] = []
                    
                    if 'error_messages' in item:
                        error_list = item['error_messages'].get('L', [])
                        results['error_messages'] = [e.get('S', '') for e in error_list[:5]]
                    else:
                        results['error_messages'] = []
                    
                    return True, results
                
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == 'ResourceNotFoundException':
                    return False, "Table not found"
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
        
        return False, "Analysis in progress"
        
    except ValueError as e:
        return False, str(e)
        
    except Exception:
        return False, "Error fetching results"
