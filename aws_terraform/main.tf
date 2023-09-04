data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "replication" {
  name               = "tf-iam-role-replication-test"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "replication" {
  statement {
    effect = "Allow"

    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
    ]

    resources = [aws_s3_bucket.source.arn]
  }

  statement {
    effect = "Allow"

    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging",
    ]

    resources = ["${aws_s3_bucket.source.arn}/*"]
  }

  statement {
    effect = "Allow"

    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
    ]

    resources = ["${aws_s3_bucket.destination.arn}/*"]
  }
}

resource "aws_iam_policy" "replication" {
  name   = "tf-iam-role-policy-replication-test"
  policy = data.aws_iam_policy_document.replication.json
}

resource "aws_iam_role_policy_attachment" "replication" {
  role       = aws_iam_role.replication.name
  policy_arn = aws_iam_policy.replication.arn
}

resource "aws_s3_bucket" "destination" {
  bucket   = "tf-test-bucket-destination-test"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "destination" {
  bucket = aws_s3_bucket.destination.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn"
    }
  }
}

resource "aws_s3_bucket_notification" "bucket_notification_destination" {
  bucket      = aws_s3_bucket.destination.id
  eventbridge = true
}

resource "aws_s3_bucket_public_access_block" "public_access_block_destination" {
  bucket = aws_s3_bucket.destination.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "destination" {
  bucket = aws_s3_bucket.destination.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_acl" "destination" {
  bucket = aws_s3_bucket.destination.id
  acl    = "private"
}

resource "aws_s3_bucket" "log_bucket_destination" {
  bucket   = "my-tf-log-bucket-destination"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket_destination" {
  bucket = aws_s3_bucket.log_bucket_destination.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "public_access_log_block_destination" {
  bucket = aws_s3_bucket.log_bucket_destination.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_configuration_destination" {
  rule {
    id      = "example-rule"
    status  = "Enabled"

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 6
    }
  }

  bucket = aws_s3_bucket.destination.id
}


resource "aws_s3_bucket_versioning" "log_bucket_destination" {
  bucket = aws_s3_bucket.log_bucket_destination.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_notification" "log_bucket_notification_destination" {
  bucket      = aws_s3_bucket.log_bucket_destination.id
  eventbridge = true
}

resource "aws_s3_bucket_acl" "log_bucket_acl_destination" {
  bucket = aws_s3_bucket.log_bucket_destination.id
  acl    = "private"
}

resource "aws_s3_bucket_logging" "destination" {
  bucket = aws_s3_bucket.destination.id

  target_bucket = aws_s3_bucket.log_bucket_destination.id
  target_prefix = "log/"
}

resource "aws_s3_bucket_lifecycle_configuration" "log_bucket_lifecycle_configuration_destination" {
  rule {
    id      = "example-rule"
    status  = "Enabled"

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 6
    }
  }

  bucket = aws_s3_bucket.log_bucket_destination.id
}

resource "aws_s3_bucket" "source" {
  bucket   = "tf-test-bucket-source-test"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "source" {
  bucket = aws_s3_bucket.source.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn"
    }
  }
}

resource "aws_s3_bucket_notification" "bucket_notification_source" {
  bucket      = aws_s3_bucket.source.id
  eventbridge = true
}

resource "aws_s3_bucket_public_access_block" "public_access_block_source" {
  bucket = aws_s3_bucket.source.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "source" {
  bucket = aws_s3_bucket.source.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_acl" "source" {
  bucket = aws_s3_bucket.source.id
  acl    = "private"
}

resource "aws_s3_bucket" "log_bucket_source" {
  bucket   = "my-tf-log-bucket-destination"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket_source" {
  bucket = aws_s3_bucket.log_bucket_source.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "public_access_log_block_source" {
  bucket = aws_s3_bucket.log_bucket_source.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "log_bucket_source" {
  bucket = aws_s3_bucket.log_bucket_source.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_notification" "log_bucket_notification_source" {
  bucket      = aws_s3_bucket.log_bucket_source.id
  eventbridge = true
}

resource "aws_s3_bucket_acl" "log_bucket_acl_source" {
  bucket = aws_s3_bucket.log_bucket_source.id
  acl    = "private"
}

resource "aws_s3_bucket_logging" "source" {
  bucket = aws_s3_bucket.source.id

  target_bucket = aws_s3_bucket.log_bucket_source.id
  target_prefix = "log/"
}

resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_configuration_source" {
  rule {
    id      = "example-rule"
    status  = "Enabled"

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 6
    }
  }

  bucket = aws_s3_bucket.source.id
}

resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_configuration_source_log" {
  rule {
    id      = "example-rule"
    status  = "Enabled"

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 6
    }
  }

  bucket = aws_s3_bucket.log_bucket_source.id
}

resource "aws_s3_bucket_replication_configuration" "replication_source" {
  # Must have bucket versioning enabled first
  depends_on = [aws_s3_bucket_versioning.source]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.source.id

  rule {
    id = "foobar"

    filter {
      prefix = "foo"
    }

    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.log_bucket_source.arn
      storage_class = "STANDARD"
    }
  }
}

resource "aws_s3_bucket_replication_configuration" "replication_source_log" {
  # Must have bucket versioning enabled first
  depends_on = [aws_s3_bucket_versioning.log_bucket_source]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.log_bucket_source.id

  rule {
    id = "foobar"

    filter {
      prefix = "foo"
    }

    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.log_bucket_source.arn
      storage_class = "STANDARD"
    }
  }
}

resource "aws_s3_bucket_replication_configuration" "replication_destination" {
  # Must have bucket versioning enabled first
  depends_on = [aws_s3_bucket_versioning.destination]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.destination.id

  rule {
    id = "foobar"

    filter {
      prefix = "foo"
    }

    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.log_bucket_destination.arn
      storage_class = "STANDARD"
    }
  }
}

resource "aws_s3_bucket_replication_configuration" "replication_destination_log" {
  # Must have bucket versioning enabled first
  depends_on = [aws_s3_bucket_versioning.log_bucket_destination]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.log_bucket_destination.id

  rule {
    id = "foobar"

    filter {
      prefix = "foo"
    }

    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.log_bucket_destination.arn
      storage_class = "STANDARD"
    }
  }
}

resource "aws_kms_key" "dynamodb_key" {
  description         = "KMS key for encrypting DynamoDB tables"
#  customer_master_key_spec = var.key_spec
  is_enabled               = true
  enable_key_rotation      = true

  policy = <<EOF
{
    "Id": "key-consolepolicy-3",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "${var.user_arn}"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow access for Key Administrators",
            "Effect": "Allow",
            "Principal": {
                "AWS": "${var.user_arn}"
            },
            "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow use of the key",
            "Effect": "Allow",
            "Principal": {
                "AWS": "${var.user_arn}"
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow attachment of persistent resources",
            "Effect": "Allow",
            "Principal": {
                "AWS": "${var.user_arn}"
            },
            "Action": [
                "kms:CreateGrant",
                "kms:ListGrants",
                "kms:RevokeGrant"
            ],
          "Resource": "*",
          "Condition": {
              "Bool": {
                  "kms:GrantIsForAWSResource": "true"
              }
          }
        }
    ]
}
EOF
}

resource "aws_dynamodb_table" "terraform_locks" {
  name         = "tf_test_bucket_source_test_locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  attribute {
    name = "LockID"
    type = "S"
  }
  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
    kms_key_arn = aws_kms_key.dynamodb_key.arn
  }
}


### MongoDB configurations ###
# Create a Project
resource "mongodbatlas_project" "atlas-project" {
  org_id = var.atlas_org_id
  name   = var.atlas_project_name
}

# Create a Database User
resource "mongodbatlas_database_user" "db-user" {
  username           = "user-test"
  password           = random_password.db-user-password.result
  project_id         = mongodbatlas_project.atlas-project.id
  auth_database_name = "admin"
  roles {
    role_name     = "readWrite"
    database_name = "${var.atlas_project_name}-db"
  }
}

# Create a Database Password
resource "random_password" "db-user-password" {
  length           = 16
  special          = true
  override_special = "_%@"
}

# Create Database IP Access List
resource "mongodbatlas_project_ip_access_list" "ip" {
  project_id = mongodbatlas_project.atlas-project.id
  ip_address = var.ip_address
}

# Create an Atlas Advanced Cluster
resource "mongodbatlas_advanced_cluster" "atlas-cluster" {
  project_id     = mongodbatlas_project.atlas-project.id
  name           = var.atlas_project_name
  cluster_type   = "REPLICASET"
  backup_enabled = true
  mongo_db_major_version = var.mongodb_version
  replication_specs {
    region_configs {
      electable_specs {
        instance_size = var.cluster_instance_size_name
        node_count    = 3
      }
      analytics_specs {
        instance_size = var.cluster_instance_size_name
        node_count    = 1
      }
      priority      = 7
      provider_name = var.cloud_provider
      region_name   = var.atlas_region
    }
  }
}