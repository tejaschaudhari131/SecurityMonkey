import os
from typing import Dict, List, Optional

class SecurityMonkeyConfig:
    def __init__(self):
        # Cloud Provider Configurations
        self.cloud_providers: Dict[str, Dict] = {
            'AWS': {
                'access_key_id': os.getenv('AWS_ACCESS_KEY_ID', ''),
                'secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY', ''),
                'region': os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
                'enabled': True
            },
            'Azure': {
                'tenant_id': os.getenv('AZURE_TENANT_ID', ''),
                'client_id': os.getenv('AZURE_CLIENT_ID', ''),
                'client_secret': os.getenv('AZURE_CLIENT_SECRET', ''),
                'subscription_id': os.getenv('AZURE_SUBSCRIPTION_ID', ''),
                'enabled': True
            },
            'GCP': {
                'project_id': os.getenv('GCP_PROJECT_ID', ''),
                'credentials_path': os.getenv('GCP_CREDENTIALS_PATH', ''),
                'enabled': True
            }
        }

        # Monitoring Configuration
        self.monitoring_config: Dict[str, Any] = {
            'interval_seconds': 3600,  # Monitoring frequency (1 hour)
            'resource_types': [
                'compute',
                'storage', 
                'networking', 
                'identity', 
                'databases'
            ],
            'log_level': 'INFO'
        }

        # Notification Configurations
        self.notification_config: Dict[str, Any] = {
            'slack': {
                'enabled': True,
                'webhook_url': os.getenv('SLACK_WEBHOOK_URL', ''),
                'channels': ['#security-alerts', '#cloud-monitoring']
            },
            'email': {
                'enabled': True,
                'smtp_config': {
                    'host': os.getenv('SMTP_HOST', 'smtp.gmail.com'),
                    'port': int(os.getenv('SMTP_PORT', 587)),
                    'username': os.getenv('SMTP_USERNAME', ''),
                    'password': os.getenv('SMTP_PASSWORD', ''),
                    'use_tls': True
                },
                'recipients': [
                    'security-team@company.com',
                    'cloud-admin@company.com'
                ]
            },
            'pagerduty': {
                'enabled': False,
                'api_key': os.getenv('PAGERDUTY_API_KEY', ''),
                'service_id': os.getenv('PAGERDUTY_SERVICE_ID', '')
            }
        }

        # Compliance Framework Configurations
        self.compliance_config: Dict[str, Any] = {
            'frameworks': {
                'CIS': {
                    'enabled': True,
                    'severity_threshold': 'HIGH',
                    'benchmark_versions': {
                        'AWS': 'v1.4.0',
                        'Azure': 'v1.3.0',
                        'GCP': 'v1.2.0'
                    }
                },
                'NIST': {
                    'enabled': True,
                    'severity_threshold': 'MEDIUM',
                    'control_families': [
                        'access_control',
                        'audit_logging',
                        'data_protection',
                        'incident_response'
                    ]
                }
            }
        }

        # Security Finding Configurations
        self.finding_config: Dict[str, Any] = {
            'severity_levels': {
                'CRITICAL': {
                    'color_code': 'RED',
                    'remediation_priority': 1
                },
                'HIGH': {
                    'color_code': 'ORANGE', 
                    'remediation_priority': 2
                },
                'MEDIUM': {
                    'color_code': 'YELLOW',
                    'remediation_priority': 3
                },
                'LOW': {
                    'color_code': 'GREEN',
                    'remediation_priority': 4
                }
            },
            'auto_remediation': {
                'enabled': True,
                'excluded_severities': ['CRITICAL']
            }
        }

        # Logging Configuration
        self.logging_config: Dict[str, Any] = {
            'log_directory': os.getenv('LOG_DIR', '/var/log/securitymonkey'),
            'log_rotation': {
                'max_bytes': 10 * 1024 * 1024,  # 10 MB
                'backup_count': 5
            },
            'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        }

    def validate_config(self) -> bool:
        """
        Validate configuration settings
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        # Check cloud provider credentials
        for provider, config in self.cloud_providers.items():
            if config['enabled']:
                if not all(config.values()):
                    print(f"Missing credentials for {provider}")
                    return False
        
        # Check notification configurations
        if self.notification_config['slack']['enabled']:
            if not self.notification_config['slack']['webhook_url']:
                print("Slack webhook URL is missing")
                return False
        
        if self.notification_config['email']['enabled']:
            email_config = self.notification_config['email']['smtp_config']
            if not all([email_config['host'], email_config['username'], email_config['password']]):
                print("Email SMTP configuration is incomplete")
                return False
        
        return True

    def get_provider_config(self, provider_name: str) -> Optional[Dict]:
        """
        Get configuration for a specific cloud provider
        
        Args:
            provider_name (str): Name of the cloud provider
        
        Returns:
            Optional configuration dictionary
        """
        return self.cloud_providers.get(provider_name)

    def to_dict(self) -> Dict:
        """
        Convert configuration to dictionary
        
        Returns:
            Dict: Full configuration dictionary
        """
        return {
            'cloud_providers': self.cloud_providers,
            'monitoring': self.monitoring_config,
            'notifications': self.notification_config,
            'compliance': self.compliance_config,
            'findings': self.finding_config,
            'logging': self.logging_config
        }

# Create a singleton configuration instance
security_monkey_config = SecurityMonkeyConfig()

# Example usage
def main():
    config = security_monkey_config
    
    # Validate configuration
    if config.validate_config():
        print("Configuration is valid")
    
    # Get AWS provider configuration
    aws_config = config.get_provider_config('AWS')
    print(aws_config)
    
    # Convert configuration to dictionary
    config_dict = config.to_dict()
    print(config_dict)

if __name__ == "__main__":
    main()
