# Multi-Cloud Resource Discovery and Security Compliance

This project is a Python-based solution for comprehensive resource discovery, anomaly detection, and compliance checks across multi-cloud environments (AWS, Azure, and GCP). It uses modern libraries and machine learning techniques to enhance cloud security and compliance automation.

## Features
- **Multi-Cloud Resource Discovery**
  - Discover EC2 instances, S3 buckets, RDS instances, IAM users, and security groups in AWS.
  - Discover Virtual Machines (VMs), Storage Accounts, and Network Security Groups in Azure.
- **Anomaly Detection**
  - Machine learning-based detection of anomalous resources using the Isolation Forest algorithm.
- **Compliance Framework Integration**
  - Evaluate cloud resources against compliance frameworks such as NIST 800-53 and PCI DSS.
  - Generate actionable recommendations for failed compliance checks.

## Requirements
- Python 3.8 or higher
- Supported cloud credentials:
  - AWS: Access keys via `boto3` or environment variables.
  - Azure: Credentials via Azure SDK.
- Dependencies listed in `requirements.txt`.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/tejaschaudhari131/SecurityMonkey.git
   cd SecurityMonkey
   ```

2. Create a virtual environment and activate it:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # For Linux/Mac
   venv\Scripts\activate     # For Windows
   ```

3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
### 1. Set Up Cloud Credentials
- **AWS**: Configure AWS CLI or set environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`).
- **Azure**: Set up credentials via `azure.identity` or Azure SDK.

### 2. Run the Script
Run the main script to perform resource discovery, anomaly detection, and compliance checks:
```bash
python main.py
```

### 3. Output
- **Anomalous Resources**: Lists cloud resources identified as anomalies.
- **Compliance Results**: Displays passed and failed compliance checks with actionable recommendations.

## Key Classes
1. `CloudResourceDiscovery`
   - Discovers resources across AWS and Azure.
2. `AdvancedSecurityChecker`
   - Uses machine learning to identify anomalous resources.
3. `ComplianceFrameworkIntegration`
   - Evaluates resources against compliance frameworks.

## Customization
You can extend the script to support additional cloud providers or compliance frameworks:
- Add new methods to the `CloudResourceDiscovery` class for other providers (e.g., GCP).
- Add compliance frameworks to the `ComplianceFrameworkIntegration` class.

## Examples
Example Output:
```json
{
  "anomalous_resources": [
    {"id": "i-0abcd1234efgh5678", "type": "t2.micro", "state": "running", "vpc_id": "vpc-12345"}
  ],
  "compliance_results": {
    "passed_checks": ["Encryption in Transit", "Firewall Configuration"],
    "failed_checks": ["Multi-factor Authentication"],
    "recommendations": ["Implement MFA for all users."]
  }
}
```

## Dependencies
See the `requirements.txt` file for all dependencies.

## Contributing
Contributions are welcome! Feel free to submit issues or pull requests.

## License
This project is licensed under the MIT License.

## Contact
For questions or suggestions, please reach out to:
- **Author**: Tejaram Chaudhari
- **Email**: tejaschaudhari131@gmail.com
- **GitHub**: @tejaschaudhari131
