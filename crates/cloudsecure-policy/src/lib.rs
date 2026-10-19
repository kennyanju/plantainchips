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

/// Catalog of standard CSPM policy rules.
pub fn standard_cspm_rules() -> Vec<PolicyRule> {
    vec![
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
            id: "CIS-AWS-3.0-2.2.1",
            title: "RDS Instances Must Enable Storage Encryption",
            severity: Severity::High,
            provider: CloudProvider::Aws,
            resource_type: "aws-rds-instance",
            rql: "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-rds-instance' and json.rule = storageEncrypted is false",
            description: "Amazon RDS database instances should have storage encryption enabled with KMS customer managed keys.",
            framework_mappings: &["CIS AWS v3.0: 2.2.1", "NIST 800-53: SC-28", "HIPAA: 164.312(a)(2)(iv)"],
            remediation_hcl: r#"# RDS storage encryption cannot be enabled directly on existing active instances.
# Step 1: Create a snapshot. Step 2: Encrypt snapshot copy. Step 3: Restore to new instance.
resource "aws_db_instance" "{{RESOURCE_ID}}" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}"#,
            remediation_cli: "aws rds copy-db-snapshot --source-db-snapshot-identifier snapshot-plain --target-db-snapshot-identifier snapshot-encrypted --kms-key-id arn:aws:kms:...",
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
  cidr_blocks       = ["10.0.0.0/8"] # Restrict to internal corporate VPN
  security_group_id = aws_security_group.{{RESOURCE_ID}}.id
}"#,
            remediation_cli: "aws ec2 revoke-security-group-ingress --group-id {{RESOURCE_ID}} --protocol tcp --port 22 --cidr 0.0.0.0/0",
        },
        PolicyRule {
            id: "CIS-AZURE-2.1-1",
            title: "Azure Storage Accounts Must Enforce HTTPS Secure Transfer",
            severity: Severity::High,
            provider: CloudProvider::Azure,
            resource_type: "azure-storage-account",
            rql: "config from cloud.resource where cloud.type = 'azure' and api.name = 'azure-storage-account' and json.rule = properties.supportsHttpsTrafficOnly is false",
            description: "Azure storage accounts should enforce secure transfer over HTTPS for REST APIs.",
            framework_mappings: &["CIS Azure v2.1: 2.1", "PCI-DSS v4.0: 4.1.2"],
            remediation_hcl: r#"resource "azurerm_storage_account" "{{RESOURCE_ID}}" {
  enable_https_traffic_only = true
}"#,
            remediation_cli: "az storage account update --name {{RESOURCE_ID}} --https-only true",
        },
        PolicyRule {
            id: "CIS-GCP-2.0-3.1",
            title: "Cloud Storage Buckets Must Enable Uniform Bucket-Level Access",
            severity: Severity::High,
            provider: CloudProvider::Gcp,
            resource_type: "gcp-storage-bucket",
            rql: "config from cloud.resource where cloud.type = 'gcp' and api.name = 'gcp-storage-bucket' and json.rule = uniformBucketLevelAccess.enabled is false",
            description: "Uniform bucket-level access unifies IAM permissions and disables per-object ACL vulnerabilities.",
            framework_mappings: &["CIS GCP v2.0: 3.1", "SOC 2: CC6.3"],
            remediation_hcl: r#"resource "google_storage_bucket" "{{RESOURCE_ID}}" {
  uniform_bucket_level_access = true
}"#,
            remediation_cli: "gcloud storage buckets update gs://{{RESOURCE_ID}} --uniform-bucket-level-access",
        },
    ]
}
