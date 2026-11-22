use chrono::Utc;
use cloudsecure_rql::RqlQuery;
use cloudsecure_types::{
    CloudProvider, Evidence, Finding, FindingStatus, RemediationFormat, RemediationPatch, Severity,
};
use sha2::{Digest, Sha256};

/// Built-in CSPM security policy definition with compliance mappings and remediation templates.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub provider: CloudProvider,
    pub resource_type: &'static str,
    pub rql: &'static str,
    pub description: &'static str,
    pub framework_mappings: &'static [&'static str],
    pub remediation_hcl: &'static str,
    pub remediation_cli: &'static str,
}

impl PolicyRule {
    /// Evaluates this rule against a resource, returning a structured Finding.
    pub fn evaluate(&self, resource: &cloudsecure_types::CloudResource) -> Option<Finding> {
        if resource.provider != self.provider {
            return None;
        }

        if !resource.resource_type.eq_ignore_ascii_case(self.resource_type)
            && !resource.service.eq_ignore_ascii_case(self.resource_type)
        {
            return None;
        }

        let parsed_query = RqlQuery::parse(self.rql).ok()?;
        let is_violation = parsed_query.evaluate(resource);

        if is_violation {
            let hcl = self.remediation_hcl.replace("{{RESOURCE_ID}}", &resource.name);
            let sha256_hash = {
                let mut hasher = Sha256::new();
                hasher.update(hcl.as_bytes());
                format!("{:x}", hasher.finalize())
            };

            let finding_id = format!("{}-{}", self.id, resource.id);
            let evidence = Evidence {
                rule_id: self.id.to_string(),
                target_path: format!("$.state (evaluated against RQL: {})", self.rql),
                expected_value: "Compliant configuration".to_string(),
                observed_value: "Violates security policy".to_string(),
                message: self.description.to_string(),
                resource_state_hash: resource.state_hash(),
            };

            Some(Finding {
                id: finding_id,
                rule_id: self.id.to_string(),
                title: self.title.to_string(),
                severity: self.severity,
                status: FindingStatus::Fail,
                provider: resource.provider,
                account_id: resource.account_id.clone(),
                region: resource.region.clone(),
                resource_id: resource.id.clone(),
                resource_arn: resource.arn.clone(),
                resource_type: resource.resource_type.clone(),
                framework_mappings: self.framework_mappings.iter().map(|s| s.to_string()).collect(),
                evidence,
                remediation: Some(RemediationPatch {
                    format: RemediationFormat::TerraformHcl,
                    code: hcl,
                    sha256_hash,
                }),
                timestamp: Utc::now(),
            })
        } else {
            None
        }
    }
}

/// Catalog of standard CSPM policy rules covering AWS, Azure, GCP, and Kubernetes.
pub fn standard_cspm_rules() -> Vec<PolicyRule> {
    vec![
        // --- AWS RULES ---
        PolicyRule {
            id: "CIS-AWS-3.0-2.1.1",
            title: "S3 Buckets Must Enable Public Access Block",
            severity: Severity::Critical,
            provider: CloudProvider::Aws,
            resource_type: "aws-s3-bucket",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-s3-bucket' and json.rule = publicAccessBlockConfiguration.restrictPublicBuckets is false",
            description: "S3 buckets should prohibit public bucket policies and ACLs to prevent unauthorized global data exposure.",
            framework_mappings: &["CIS AWS v3.0: 2.1.1", "SOC 2: CC6.1", "PCI-DSS v4.0: 1.2.1"],
            remediation_hcl: r#"resource "aws_s3_bucket_public_access_block" "{{RESOURCE_ID}}_block" {
  bucket = aws_s3_bucket.{{RESOURCE_ID}}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}"#,
            remediation_cli: "aws s3api put-public-access-block --bucket {{RESOURCE_ID}} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-2.1.2",
            title: "S3 Buckets Must Enable Server-Side Encryption (SSE-KMS)",
            severity: Severity::High,
            provider: CloudProvider::Aws,
            resource_type: "aws-s3-bucket",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-s3-bucket' and json.rule = serverSideEncryptionConfiguration.rules[].applyServerSideEncryptionByDefault.sseAlgorithm != 'aws:kms'",
            description: "S3 buckets must be encrypted at rest using KMS Customer Managed Keys.",
            framework_mappings: &["CIS AWS v3.0: 2.1.2", "NIST 800-53: SC-28", "HIPAA: 164.312(a)(2)(iv)"],
            remediation_hcl: r#"resource "aws_s3_bucket_server_side_encryption_configuration" "{{RESOURCE_ID}}_enc" {
  bucket = aws_s3_bucket.{{RESOURCE_ID}}.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3.arn
      sse_algorithm     = "aws:kms"
    }
  }
}"#,
            remediation_cli: "aws s3api put-bucket-encryption --bucket {{RESOURCE_ID}} --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-2.1.3",
            title: "S3 Buckets Must Enable Versioning and MFA Delete",
            severity: Severity::Medium,
            provider: CloudProvider::Aws,
            resource_type: "aws-s3-bucket",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-s3-bucket' and json.rule = versioning.status != 'Enabled'",
            description: "S3 bucket versioning preserves historical object states and protects against accidental or malicious deletion.",
            framework_mappings: &["CIS AWS v3.0: 2.1.3", "SOC 2: CC6.8", "ISO 27001: A.8.13"],
            remediation_hcl: r#"resource "aws_s3_bucket_versioning" "{{RESOURCE_ID}}_ver" {
  bucket = aws_s3_bucket.{{RESOURCE_ID}}.id
  versioning_configuration {
    status = "Enabled"
  }
}"#,
            remediation_cli: "aws s3api put-bucket-versioning --bucket {{RESOURCE_ID}} --versioning-configuration Status=Enabled",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-2.2.1",
            title: "RDS Instances Must Enable Storage Encryption",
            severity: Severity::High,
            provider: CloudProvider::Aws,
            resource_type: "aws-rds-instance",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-rds-instance' and json.rule = storageEncrypted is false",
            description: "Amazon RDS database instances should have storage encryption enabled with KMS customer managed keys.",
            framework_mappings: &["CIS AWS v3.0: 2.2.1", "NIST 800-53: SC-28", "HIPAA: 164.312(a)(2)(iv)"],
            remediation_hcl: r#"resource "aws_db_instance" "{{RESOURCE_ID}}" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}"#,
            remediation_cli: "aws rds copy-db-snapshot --source-db-snapshot-identifier snap-unenc --target-db-snapshot-identifier snap-enc --kms-key-id arn:aws:kms:...",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-2.2.2",
            title: "RDS Instances Must Prohibit Public Accessibility",
            severity: Severity::Critical,
            provider: CloudProvider::Aws,
            resource_type: "aws-rds-instance",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-rds-instance' and json.rule = publiclyAccessible is true",
            description: "Database instances should reside in private subnets without public internet route tables.",
            framework_mappings: &["CIS AWS v3.0: 2.2.2", "PCI-DSS v4.0: 1.3.1", "SOC 2: CC6.6"],
            remediation_hcl: r#"resource "aws_db_instance" "{{RESOURCE_ID}}" {
  publicly_accessible = false
}"#,
            remediation_cli: "aws rds modify-db-instance --db-instance-identifier {{RESOURCE_ID}} --no-publicly-accessible --apply-immediately",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-2.2.3",
            title: "EBS Encryption By Default Must Be Enforced",
            severity: Severity::High,
            provider: CloudProvider::Aws,
            resource_type: "aws-ec2-instance",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-ec2-instance' and json.rule = blockDeviceMapping[].ebs.encrypted is false",
            description: "Elastic Block Store volumes attached to EC2 instances must be encrypted at rest.",
            framework_mappings: &["CIS AWS v3.0: 2.2.3", "NIST 800-53: SC-28", "SOC 2: CC6.1"],
            remediation_hcl: r#"resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}"#,
            remediation_cli: "aws ec2 enable-ebs-encryption-by-default",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-4.1",
            title: "Security Groups Must Not Permit Ingress From 0.0.0.0/0 to Port 22",
            severity: Severity::Critical,
            provider: CloudProvider::Aws,
            resource_type: "aws-security-group",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-security-group' and json.rule = ipPermissions[].fromPort = 22 and json.rule = ipPermissions[].ipRanges[].cidrIp = '0.0.0.0/0'",
            description: "Security groups must not allow open ingress to port 22 (SSH) from the public Internet (0.0.0.0/0).",
            framework_mappings: &["CIS AWS v3.0: 4.1", "PCI-DSS v4.0: 1.3.1", "SOC 2: CC6.6"],
            remediation_hcl: r#"resource "aws_security_group_rule" "restricted_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.{{RESOURCE_ID}}.id
}"#,
            remediation_cli: "aws ec2 revoke-security-group-ingress --group-id {{RESOURCE_ID}} --protocol tcp --port 22 --cidr 0.0.0.0/0",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-4.2",
            title: "Security Groups Must Not Permit Ingress From 0.0.0.0/0 to Port 3389",
            severity: Severity::Critical,
            provider: CloudProvider::Aws,
            resource_type: "aws-security-group",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-security-group' and json.rule = ipPermissions[].fromPort = 3389 and json.rule = ipPermissions[].ipRanges[].cidrIp = '0.0.0.0/0'",
            description: "Security groups must not allow open ingress to port 3389 (RDP) from the public Internet.",
            framework_mappings: &["CIS AWS v3.0: 4.2", "PCI-DSS v4.0: 1.3.1", "SOC 2: CC6.6"],
            remediation_hcl: r#"resource "aws_security_group_rule" "restricted_rdp" {
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.{{RESOURCE_ID}}.id
}"#,
            remediation_cli: "aws ec2 revoke-security-group-ingress --group-id {{RESOURCE_ID}} --protocol tcp --port 3389 --cidr 0.0.0.0/0",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-4.3",
            title: "Security Groups Must Not Permit Ingress From 0.0.0.0/0 to Database Ports",
            severity: Severity::Critical,
            provider: CloudProvider::Aws,
            resource_type: "aws-security-group",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-security-group' and json.rule = ipPermissions[].fromPort in (3306, 5432, 6379, 27017) and json.rule = ipPermissions[].ipRanges[].cidrIp = '0.0.0.0/0'",
            description: "Direct internet ingress to database ports (MySQL, PostgreSQL, Redis, MongoDB) violates network microsegmentation boundaries.",
            framework_mappings: &["CIS AWS v3.0: 4.3", "PCI-DSS v4.0: 1.2.1", "NIST 800-53: SC-7"],
            remediation_hcl: r#"resource "aws_security_group_rule" "private_db" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  source_security_group_id = aws_security_group.app_tier.id
  security_group_id        = aws_security_group.{{RESOURCE_ID}}.id
}"#,
            remediation_cli: "aws ec2 revoke-security-group-ingress --group-id {{RESOURCE_ID}} --protocol tcp --port 5432 --cidr 0.0.0.0/0",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-5.6",
            title: "EC2 Instances Must Enforce IMDSv2",
            severity: Severity::High,
            provider: CloudProvider::Aws,
            resource_type: "aws-ec2-instance",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-ec2-instance' and json.rule = metadataOptions.httpTokens != 'required'",
            description: "Enforce IMDSv2 token-based session authentication on EC2 instances to prevent SSRF credential theft.",
            framework_mappings: &["CIS AWS v3.0: 5.6", "SOC 2: CC6.6", "PCI-DSS v4.0: 6.2.4"],
            remediation_hcl: r#"resource "aws_instance" "{{RESOURCE_ID}}" {
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}"#,
            remediation_cli: "aws ec2 modify-instance-metadata-options --instance-id {{RESOURCE_ID}} --http-tokens required --http-endpoint enabled",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-3.1",
            title: "CloudTrail Multi-Region Logging Must Be Enabled",
            severity: Severity::High,
            provider: CloudProvider::Aws,
            resource_type: "aws-cloudtrail",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-cloudtrail' and json.rule = isMultiRegionTrail is false",
            description: "Multi-region CloudTrail trails guarantee audit telemetry across all AWS regions, preventing blind spots.",
            framework_mappings: &["CIS AWS v3.0: 3.1", "SOC 2: CC7.2", "PCI-DSS v4.0: 10.2.1"],
            remediation_hcl: r#"resource "aws_cloudtrail" "{{RESOURCE_ID}}" {
  name                          = "{{RESOURCE_ID}}"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
}"#,
            remediation_cli: "aws cloudtrail update-trail --name {{RESOURCE_ID}} --is-multi-region-trail",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-3.2",
            title: "CloudTrail Log File Validation Must Be Enabled",
            severity: Severity::Medium,
            provider: CloudProvider::Aws,
            resource_type: "aws-cloudtrail",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-cloudtrail' and json.rule = logFileValidationEnabled is false",
            description: "Log file validation provides cryptographic SHA-256 digests ensuring forensic audit trails cannot be altered.",
            framework_mappings: &["CIS AWS v3.0: 3.2", "NIST 800-53: AU-9", "ISO 27001: A.8.15"],
            remediation_hcl: r#"resource "aws_cloudtrail" "{{RESOURCE_ID}}" {
  enable_log_file_validation = true
}"#,
            remediation_cli: "aws cloudtrail update-trail --name {{RESOURCE_ID}} --enable-log-file-validation",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-3.6",
            title: "KMS Customer Managed Keys Must Enable Automatic Rotation",
            severity: Severity::Medium,
            provider: CloudProvider::Aws,
            resource_type: "aws-kms-key",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-kms-key' and json.rule = keyRotationEnabled is false",
            description: "KMS customer managed keys should automatically rotate backing material every 365 days.",
            framework_mappings: &["CIS AWS v3.0: 3.6", "PCI-DSS v4.0: 3.6.4", "SOC 2: CC6.1"],
            remediation_hcl: r#"resource "aws_kms_key" "{{RESOURCE_ID}}" {
  enable_key_rotation = true
}"#,
            remediation_cli: "aws kms enable-key-rotation --key-id {{RESOURCE_ID}}",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-1.5",
            title: "AWS Root Account Must Have MFA Enabled",
            severity: Severity::Critical,
            provider: CloudProvider::Aws,
            resource_type: "aws-iam-account-summary",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-iam-account-summary' and json.rule = accountMFAEnabled is false",
            description: "The AWS root account possesses unrestricted superuser rights and must be protected by hardware or virtual MFA.",
            framework_mappings: &["CIS AWS v3.0: 1.5", "PCI-DSS v4.0: 8.3.1", "SOC 2: CC6.1"],
            remediation_hcl: r#"# Root MFA cannot be configured via Terraform. Log into AWS Console with root credentials and enable FIDO2/Virtual MFA."#,
            remediation_cli: "aws iam create-virtual-mfa-device --virtual-mfa-device-name root-hardware-mfa --outfile /tmp/qr.png",
        },
        PolicyRule {
            id: "CIS-AWS-3.0-1.16",
            title: "IAM Policies Must Not Grant Unrestricted Wildcard Administrator Rights",
            severity: Severity::Critical,
            provider: CloudProvider::Aws,
            resource_type: "aws-iam-policy",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-iam-policy' and json.rule = document.Statement[].Action = '*' and json.rule = document.Statement[].Resource = '*'",
            description: "IAM policies granting Action: * on Resource: * violate the principle of least privilege.",
            framework_mappings: &["CIS AWS v3.0: 1.16", "SOC 2: CC6.3", "NIST 800-53: AC-6"],
            remediation_hcl: r#"# Replace wildcard policy with scoped role permissions using AWS managed policies or specific action list."#,
            remediation_cli: "aws iam detach-role-policy --role-name {{RESOURCE_ID}} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        },

        // --- AZURE RULES ---
        PolicyRule {
            id: "CIS-AZURE-2.1-1",
            title: "Azure Storage Accounts Must Enforce HTTPS Secure Transfer",
            severity: Severity::High,
            provider: CloudProvider::Azure,
            resource_type: "azure-storage-account",
            rql: "config from cloud.resource where cloud.type = 'azure' and api.name = 'azure-storage-account' and json.rule = properties.supportsHttpsTrafficOnly is false",
            description: "Azure storage accounts should enforce secure transfer over HTTPS for REST APIs.",
            framework_mappings: &["CIS Azure v2.1: 2.1", "PCI-DSS v4.0: 4.1.2", "HIPAA: 164.312(e)(1)"],
            remediation_hcl: r#"resource "azurerm_storage_account" "{{RESOURCE_ID}}" {
  enable_https_traffic_only = true
}"#,
            remediation_cli: "az storage account update --name {{RESOURCE_ID}} --https-only true",
        },
        PolicyRule {
            id: "CIS-AZURE-2.1-2",
            title: "Azure Storage Accounts Must Disable Public Blob Access",
            severity: Severity::Critical,
            provider: CloudProvider::Azure,
            resource_type: "azure-storage-account",
            rql: "config from cloud.resource where cloud.type = 'azure' and api.name = 'azure-storage-account' and json.rule = properties.allowBlobPublicAccess is true",
            description: "Anonymous public read access to containers and blobs must be prohibited at the storage account level.",
            framework_mappings: &["CIS Azure v2.1: 2.2", "SOC 2: CC6.1", "PCI-DSS v4.0: 1.2.1"],
            remediation_hcl: r#"resource "azurerm_storage_account" "{{RESOURCE_ID}}" {
  allow_nested_items_to_be_public = false
}"#,
            remediation_cli: "az storage account update --name {{RESOURCE_ID}} --allow-blob-public-access false",
        },
        PolicyRule {
            id: "CIS-AZURE-2.1-4.1",
            title: "Azure SQL Database Must Enable Transparent Data Encryption (TDE)",
            severity: Severity::High,
            provider: CloudProvider::Azure,
            resource_type: "azure-sql-database",
            rql: "config from cloud.resource where cloud.type = 'azure' and api.name = 'azure-sql-database' and json.rule = properties.status != 'Enabled'",
            description: "Transparent Data Encryption protects Azure SQL databases against unauthorized read activity by encrypting data at rest.",
            framework_mappings: &["CIS Azure v2.1: 4.1", "NIST 800-53: SC-28", "PCI-DSS v4.0: 3.4"],
            remediation_hcl: r#"resource "azurerm_mssql_database" "{{RESOURCE_ID}}" {
  transparent_data_encryption_enabled = true
}"#,
            remediation_cli: "az sql db tde set --database {{RESOURCE_ID}} --server my-server --status Enabled",
        },
        PolicyRule {
            id: "CIS-AZURE-2.1-6.1",
            title: "Azure Network Security Groups Must Not Allow Inbound RDP (Port 3389)",
            severity: Severity::Critical,
            provider: CloudProvider::Azure,
            resource_type: "azure-network-security-group",
            rql: "config from cloud.resource where cloud.type = 'azure' and api.name = 'azure-network-security-group' and json.rule = properties.securityRules[].properties.destinationPortRange = '3389' and json.rule = properties.securityRules[].properties.sourceAddressPrefix = '*'",
            description: "Network Security Groups must prohibit inbound RDP access from any source IP prefix (*).",
            framework_mappings: &["CIS Azure v2.1: 6.1", "PCI-DSS v4.0: 1.3.1", "SOC 2: CC6.6"],
            remediation_hcl: r#"resource "azurerm_network_security_rule" "deny_rdp" {
  name                        = "Deny_RDP"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  network_security_group_name = "{{RESOURCE_ID}}"
}"#,
            remediation_cli: "az network nsg rule delete --name Allow-RDP --nsg-name {{RESOURCE_ID}} --resource-group my-rg",
        },
        PolicyRule {
            id: "CIS-AZURE-2.1-8.1",
            title: "Azure Key Vault Must Enable Soft Delete and Purge Protection",
            severity: Severity::High,
            provider: CloudProvider::Azure,
            resource_type: "azure-key-vault",
            rql: "config from cloud.resource where cloud.type = 'azure' and api.name = 'azure-key-vault' and json.rule = properties.enablePurgeProtection is false",
            description: "Purge protection prevents malicious permanent deletion of keys and secrets during security incidents.",
            framework_mappings: &["CIS Azure v2.1: 8.1", "SOC 2: CC6.1", "ISO 27001: A.8.24"],
            remediation_hcl: r#"resource "azurerm_key_vault" "{{RESOURCE_ID}}" {
  purge_protection_enabled = true
  soft_delete_retention_days = 90
}"#,
            remediation_cli: "az keyvault update --name {{RESOURCE_ID}} --enable-purge-protection true",
        },

        // --- GCP RULES ---
        PolicyRule {
            id: "CIS-GCP-2.0-3.1",
            title: "Cloud Storage Buckets Must Enable Uniform Bucket-Level Access",
            severity: Severity::High,
            provider: CloudProvider::Gcp,
            resource_type: "gcp-storage-bucket",
            rql: "config from cloud.resource where cloud.type = 'gcp' and api.name = 'gcp-storage-bucket' and json.rule = uniformBucketLevelAccess.enabled is false",
            description: "Uniform bucket-level access unifies IAM permissions and disables per-object ACL vulnerabilities.",
            framework_mappings: &["CIS GCP v2.0: 3.1", "SOC 2: CC6.3", "PCI-DSS v4.0: 1.2.1"],
            remediation_hcl: r#"resource "google_storage_bucket" "{{RESOURCE_ID}}" {
  uniform_bucket_level_access = true
}"#,
            remediation_cli: "gcloud storage buckets update gs://{{RESOURCE_ID}} --uniform-bucket-level-access",
        },
        PolicyRule {
            id: "CIS-GCP-2.0-3.2",
            title: "Cloud Storage Bucket IAM Must Not Grant Permissions to allUsers",
            severity: Severity::Critical,
            provider: CloudProvider::Gcp,
            resource_type: "gcp-storage-bucket",
            rql: "config from cloud.resource where cloud.type = 'gcp' and api.name = 'gcp-storage-bucket' and json.rule = iamConfiguration.publicAccessPrevention != 'enforced'",
            description: "Enforce public access prevention to prevent any object in GCS buckets from being shared with allUsers.",
            framework_mappings: &["CIS GCP v2.0: 3.2", "PCI-DSS v4.0: 1.2.1", "SOC 2: CC6.1"],
            remediation_hcl: r#"resource "google_storage_bucket" "{{RESOURCE_ID}}" {
  public_access_prevention = "enforced"
}"#,
            remediation_cli: "gcloud storage buckets update gs://{{RESOURCE_ID}} --public-access-prevention",
        },
        PolicyRule {
            id: "CIS-GCP-2.0-6.1",
            title: "Cloud SQL Instances Must Not Have Public IP Addresses",
            severity: Severity::Critical,
            provider: CloudProvider::Gcp,
            resource_type: "gcp-sql-instance",
            rql: "config from cloud.resource where cloud.type = 'gcp' and api.name = 'gcp-sql-instance' and json.rule = settings.ipConfiguration.ipv4Enabled is true",
            description: "Cloud SQL instances should exclusively use Private IP connected to VPC peering.",
            framework_mappings: &["CIS GCP v2.0: 6.1", "PCI-DSS v4.0: 1.3.1", "NIST 800-53: SC-7"],
            remediation_hcl: r#"resource "google_sql_database_instance" "{{RESOURCE_ID}}" {
  settings {
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
  }
}"#,
            remediation_cli: "gcloud sql instances patch {{RESOURCE_ID}} --no-assign-ip",
        },
        PolicyRule {
            id: "CIS-GCP-2.0-4.1",
            title: "Compute Engine Instances Must Enable OS Login",
            severity: Severity::Medium,
            provider: CloudProvider::Gcp,
            resource_type: "gcp-compute-instance",
            rql: "config from cloud.resource where cloud.type = 'gcp' and api.name = 'gcp-compute-instance' and json.rule = metadata.items[].key = 'enable-oslogin' and json.rule = metadata.items[].value != 'TRUE'",
            description: "OS Login links Linux user accounts to Google identity and 2FA credentials.",
            framework_mappings: &["CIS GCP v2.0: 4.1", "SOC 2: CC6.1", "PCI-DSS v4.0: 8.3.1"],
            remediation_hcl: r#"resource "google_compute_instance" "{{RESOURCE_ID}}" {
  metadata = {
    enable-oslogin = "TRUE"
  }
}"#,
            remediation_cli: "gcloud compute instances add-metadata {{RESOURCE_ID}} --metadata enable-oslogin=TRUE",
        },
        PolicyRule {
            id: "CIS-GCP-2.0-7.1",
            title: "GKE Clusters Must Enable Workload Identity",
            severity: Severity::High,
            provider: CloudProvider::Gcp,
            resource_type: "gcp-gke-cluster",
            rql: "config from cloud.resource where cloud.type = 'gcp' and api.name = 'gcp-gke-cluster' and json.rule = workloadIdentityConfig.workloadPool is empty",
            description: "Workload Identity securely connects Kubernetes service accounts to GCP IAM without static JSON keys.",
            framework_mappings: &["CIS GCP v2.0: 7.1", "SOC 2: CC6.3", "NIST 800-53: AC-6"],
            remediation_hcl: r#"resource "google_container_cluster" "{{RESOURCE_ID}}" {
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
}"#,
            remediation_cli: "gcloud container clusters update {{RESOURCE_ID}} --workload-pool=PROJECT_ID.svc.id.goog",
        },

        // --- KUBERNETES RULES ---
        PolicyRule {
            id: "CIS-K8S-1.8-5.1.1",
            title: "Kubernetes Pods Must Not Run In Privileged Mode",
            severity: Severity::Critical,
            provider: CloudProvider::Kubernetes,
            resource_type: "k8s-pod",
            rql: "config from cloud.resource where cloud.type = 'kubernetes' and api.name = 'k8s-pod' and json.rule = spec.containers[].securityContext.privileged is true",
            description: "Privileged containers share the host kernel namespace and can break out to achieve host node root takeover.",
            framework_mappings: &["CIS K8s v1.8: 5.1.1", "PCI-DSS v4.0: 2.2.4", "SOC 2: CC6.6"],
            remediation_hcl: r#"spec:
  containers:
  - name: app
    securityContext:
      privileged: false
      allowPrivilegeEscalation: false"#,
            remediation_cli: "kubectl patch pod {{RESOURCE_ID}} --type='json' -p='[{\"op\": \"replace\", \"path\": \"/spec/containers/0/securityContext/privileged\", \"value\": false}]'",
        },
        PolicyRule {
            id: "CIS-K8S-1.8-5.1.2",
            title: "Kubernetes Containers Must Not Run As Root (UID 0)",
            severity: Severity::High,
            provider: CloudProvider::Kubernetes,
            resource_type: "k8s-pod",
            rql: "config from cloud.resource where cloud.type = 'kubernetes' and api.name = 'k8s-pod' and json.rule = spec.securityContext.runAsNonRoot is false",
            description: "Containers must specify runAsNonRoot: true to guarantee process execution under an unprivileged UID.",
            framework_mappings: &["CIS K8s v1.8: 5.1.2", "NIST 800-53: AC-6", "SOC 2: CC6.3"],
            remediation_hcl: r#"spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001"#,
            remediation_cli: "kubectl patch deployment {{RESOURCE_ID}} -p '{\"spec\":{\"template\":{\"spec\":{\"securityContext\":{\"runAsNonRoot\":true}}}}}'",
        },
        PolicyRule {
            id: "CIS-K8S-1.8-5.1.5",
            title: "Kubernetes Pods Must Not Share Host Network or Host PID",
            severity: Severity::Critical,
            provider: CloudProvider::Kubernetes,
            resource_type: "k8s-pod",
            rql: "config from cloud.resource where cloud.type = 'kubernetes' and api.name = 'k8s-pod' and json.rule = spec.hostNetwork is true",
            description: "Pods sharing the host network can sniff loopback traffic and access link-local cloud metadata.",
            framework_mappings: &["CIS K8s v1.8: 5.1.5", "PCI-DSS v4.0: 1.3.1", "SOC 2: CC6.6"],
            remediation_hcl: r#"spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false"#,
            remediation_cli: "kubectl patch deployment {{RESOURCE_ID}} -p '{\"spec\":{\"template\":{\"spec\":{\"hostNetwork\":false}}}}'",
        },
    ]
}
