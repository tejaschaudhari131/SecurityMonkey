import boto3
import azure.mgmt.resource
from azure.identity import DefaultAzureCredential
import google.cloud.compute_v1
import logging
import json
import asyncio
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from typing import Dict, List, Any
import jsonschema
from cryptography.fernet import Fernet

class CloudResourceDiscovery:
    """Comprehensive multi-cloud resource discovery"""

    @classmethod
    async def discover_aws_resources(cls, session):
        """Detailed AWS resource discovery"""
        resources = {
            'ec2_instances': [],
            's3_buckets': [],
            'security_groups': [],
            'iam_users': [],
            'rds_instances': []
        }

        try:
            # EC2 Instances
            ec2_client = session.client('ec2')
            instances = ec2_client.describe_instances()
            resources['ec2_instances'] = [
                {
                    'id': instance['InstanceId'],
                    'type': instance['InstanceType'],
                    'state': instance['State']['Name'],
                    'vpc_id': instance.get('VpcId'),
                    'security_groups': [sg['GroupId'] for sg in instance['SecurityGroups']]
                } for reservation in instances['Reservations']
                for instance in reservation['Instances']
            ]

            # S3 Buckets
            s3_client = session.client('s3')
            buckets = s3_client.list_buckets()
            resources['s3_buckets'] = [
                {
                    'name': bucket['Name'],
                    'creation_date': bucket['CreationDate'],
                    'region': s3_client.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
                } for bucket in buckets['Buckets']
            ]

            # Security Groups
            security_groups = ec2_client.describe_security_groups()
            resources['security_groups'] = [
                {
                    'id': sg['GroupId'],
                    'name': sg['GroupName'],
                    'description': sg['Description'],
                    'inbound_rules': sg['IpPermissions'],
                    'outbound_rules': sg['IpPermissionsEgress']
                } for sg in security_groups['SecurityGroups']
            ]

            # IAM Users
            iam_client = session.client('iam')
            users = iam_client.list_users()
            resources['iam_users'] = [
                {
                    'username': user['UserName'],
                    'id': user['UserId'],
                    'arn': user['Arn'],
                    'created_date': user['CreateDate']
                } for user in users['Users']
            ]

            # RDS Instances
            rds_client = session.client('rds')
            db_instances = rds_client.describe_db_instances()
            resources['rds_instances'] = [
                {
                    'id': instance['DBInstanceIdentifier'],
                    'engine': instance['Engine'],
                    'status': instance['DBInstanceStatus'],
                    'endpoint': instance.get('Endpoint', {}).get('Address'),
                    'publicly_accessible': instance['PubliclyAccessible']
                } for instance in db_instances['DBInstances']
            ]

        except Exception as e:
            logging.error(f"AWS resource discovery error: {e}")

        return resources

    @classmethod
    async def discover_azure_resources(cls, credentials):
        """Detailed Azure resource discovery"""
        resources = {
            'vms': [],
            'storage_accounts': [],
            'network_security_groups': [],
            'sql_databases': []
        }

        try:
            # Azure VM Discovery
            compute_client = azure.mgmt.compute.ComputeManagementClient(credentials, '<SUBSCRIPTION_ID>')
            vms = list(compute_client.virtual_machines.list_all())
            resources['vms'] = [
                {
                    'id': vm.id,
                    'name': vm.name,
                    'location': vm.location,
                    'size': vm.hardware_profile.vm_size,
                    'os_type': vm.storage_profile.os_disk.os_type
                } for vm in vms
            ]

            # Storage Account Discovery
            storage_client = azure.mgmt.storage.StorageManagementClient(credentials, '<SUBSCRIPTION_ID>')
            storage_accounts = list(storage_client.storage_accounts.list())
            resources['storage_accounts'] = [
                {
                    'id': account.id,
                    'name': account.name,
                    'location': account.location,
                    'kind': account.kind,
                    'sku': account.sku.name
                } for account in storage_accounts
            ]

            # Network Security Groups
            network_client = azure.mgmt.network.NetworkManagementClient(credentials, '<SUBSCRIPTION_ID>')
            nsgs = list(network_client.network_security_groups.list_all())
            resources['network_security_groups'] = [
                {
                    'id': nsg.id,
                    'name': nsg.name,
                    'location': nsg.location,
                    'security_rules': [
                        {
                            'name': rule.name,
                            'priority': rule.priority,
                            'protocol': rule.protocol,
                            'access': rule.access
                        } for rule in nsg.security_rules
                    ]
                } for nsg in nsgs
            ]

        except Exception as e:
            logging.error(f"Azure resource discovery error: {e}")

        return resources


class AdvancedSecurityChecker:
    """Enhanced security checking with ML-based anomaly detection"""

    def __init__(self):
        self.ml_detector = IsolationForest(
            contamination=0.1,  # 10% expected anomalies
            random_state=42
        )

    def detect_resource_anomalies(self, resources):
        """ML-based anomaly detection for resources"""
        # Convert resources to feature matrix
        features = self._extract_features(resources)

        # Fit and predict anomalies
        anomaly_labels = self.ml_detector.fit_predict(features)

        # Identify and return anomalous resources
        anomalous_resources = [
            resource for resource, label in zip(resources, anomaly_labels)
            if label == -1  # Anomaly indicator
        ]

        return anomalous_resources

    def _extract_features(self, resources):
        """Extract numerical features for anomaly detection"""
        feature_matrix = []
        for resource in resources:
            features = [
                len(resource.get('security_groups', [])),
                len(resource.get('size', 0)),
                pd.to_datetime(resource.get('creation_date', pd.Timestamp.now())).timestamp()
            ]
            feature_matrix.append(features)

        return np.array(feature_matrix)


class ComplianceFrameworkIntegration:
    """Comprehensive compliance framework integration"""

    COMPLIANCE_FRAMEWORKS = {
        'NIST_800_53': {
            'access_control': [
                'Multi-factor Authentication',
                'Least Privilege Principle',
                'Regular Access Reviews'
            ],
            'data_protection': [
                'Encryption at Rest',
                'Encryption in Transit',
                'Data Masking'
            ]
        },
        'PCI_DSS': {
            'network_security': [
                'Firewall Configuration',
                'Segmentation',
                'Intrusion Detection'
            ],
            'data_security': [
                'Encryption Requirements',
                'Secure Data Transmission',
                'Access Logging'
            ]
        }
    }

    @classmethod
    def check_compliance(cls, resources, framework='NIST_800_53'):
        """Comprehensive compliance checking"""
        compliance_results = {
            'passed_checks': [],
            'failed_checks': [],
            'recommendations': []
        }

        framework_rules = cls.COMPLIANCE_FRAMEWORKS.get(framework, {})
        for category, checks in framework_rules.items():
            for check in checks:
                if cls.evaluate_check(check, resources):
                    compliance_results['passed_checks'].append(check)
                else:
                    compliance_results['failed_checks'].append(check)
                    compliance_results['recommendations'].append(cls.get_recommendation(check))

        return compliance_results

    @staticmethod
def evaluate_check(check, resources):
    """
    Evaluate compliance check against resources.
    
    Args:
        check (str): The specific compliance check to evaluate.
        resources (List[Dict]): The list of cloud resources to validate.
    
    Returns:
        bool: True if the check passes for all applicable resources, False otherwise.
    """
    if check == 'Multi-factor Authentication':
        # Example: Check if all IAM users have MFA enabled
        for resource in resources:
            if resource.get('type') == 'iam_user' and not resource.get('mfa_enabled', False):
                return False
        return True

    elif check == 'Encryption at Rest':
        # Example: Verify encryption for storage services
        for resource in resources:
            if resource.get('type') in ['s3_bucket', 'storage_account']:
                if not resource.get('encryption_enabled', False):
                    return False
        return True

    elif check == 'Firewall Configuration':
        # Example: Validate presence of firewall rules for security groups
        for resource in resources:
            if resource.get('type') == 'security_group' and not resource.get('firewall_rules', []):
                return False
        return True

    # Add additional checks as needed
    else:
        logging.warning(f"Check '{check}' is not implemented.")
        return False


    @staticmethod
    def get_recommendation(check):
        """Provide recommendations based on failed checks"""
        recommendations = {
            'Multi-factor Authentication': 'Implement MFA for all users.',
            'Least Privilege Principle': 'Review user permissions and reduce access rights.',
            'Regular Access Reviews': 'Schedule quarterly access reviews.',
            'Encryption at Rest': 'Enable encryption for all storage services.',
            'Encryption in Transit': 'Use TLS for all data in transit.',
            'Data Masking': 'Implement data masking for sensitive information.',
            'Firewall Configuration': 'Review and update firewall rules regularly.',
            'Segmentation': 'Segment networks to limit access to sensitive data.',
            'Intrusion Detection': 'Deploy intrusion detection systems.',
            'Encryption Requirements': 'Ensure all sensitive data is encrypted.',
            'Secure Data Transmission': 'Use secure protocols for data transmission.',
            'Access Logging': 'Enable logging for all access to sensitive data.'
        }
        return recommendations.get(check, 'No specific recommendation available.')


# Example usage
async def main():
    aws_session = boto3.Session()
    azure_credentials = DefaultAzureCredential()

    # Resource discovery
    resources_aws = await CloudResourceDiscovery.discover_aws_resources(aws_session)
    resources_azure = await CloudResourceDiscovery.discover_azure_resources(azure_credentials)

    # Combine resources for anomaly detection
    combined_resources = resources_aws['ec2_instances'] + resources_azure['vms']

    anomaly_checker = AdvancedSecurityChecker()
    anomalies = anomaly_checker.detect_resource_anomalies(combined_resources)

    compliance_results = ComplianceFrameworkIntegration.check_compliance(combined_resources)

    print("Anomalous Resources:", anomalies)
    print("Compliance Results:", compliance_results)


# Run the main function
if __name__ == "__main__":
    asyncio.run(main())
