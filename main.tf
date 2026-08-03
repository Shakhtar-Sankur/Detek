 terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "data-leak-detection-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = false

  tags = {
    Environment = var.environment
    Project     = "data-leak-detection"
  }
}

resource "aws_s3_bucket" "data_storage" {
  bucket = "${var.project_name}-data-storage-${var.environment}"

  tags = {
    Name        = "Data storage bucket"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data_storage_encryption" {
  bucket = aws_s3_bucket.data_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_dynamodb_table" "detection_state" {
  name         = "${var.project_name}-detection-state-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name        = "Detection state table"
    Environment = var.environment
  }
}

resource "aws_dynamodb_table" "alerts" {
  name         = "${var.project_name}-alerts-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "alert_id"
  range_key    = "timestamp"

  attribute {
    name = "alert_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "N"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  global_secondary_index {
    name               = "severity-timestamp-index"
    hash_key           = "severity"
    range_key          = "timestamp"
    projection_type    = "ALL"
  }

  tags = {
    Name        = "Alerts table"
    Environment = var.environment
  }
}

resource "aws_kinesis_stream" "data_collection" {
  name             = "${var.project_name}-data-collection-${var.environment}"
  shard_count      = 8
  retention_period = 48

  shard_level_metrics = [
    "IncomingBytes",
    "OutgoingBytes",
    "IncomingRecords",
    "OutgoingRecords"
  ]

  tags = {
    Name        = "Data collection stream"
    Environment = var.environment
  }
}

resource "aws_sagemaker_model" "content_classifier" {
  name               = "${var.project_name}-content-classifier-${var.environment}"
  execution_role_arn = aws_iam_role.sagemaker_execution_role.arn

  primary_container {
    image          = "${var.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/data-leak-detection:content-classifier-latest"
    model_data_url = "s3://${aws_s3_bucket.data_storage.bucket}/models/content-classifier/model.tar.gz"
  }

  tags = {
    Name        = "Content classifier model"
    Environment = var.environment
  }
}

resource "aws_lambda_function" "data_processor" {
  function_name    = "${var.project_name}-data-processor-${var.environment}"
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "data_processor.handler"
  runtime          = "python3.9"
  timeout          = 300
  memory_size      = 1024

  s3_bucket        = aws_s3_bucket.code_bucket.bucket
  s3_key           = "lambda/data_processor.zip"

  environment {
    variables = {
      DYNAMODB_STATE_TABLE = aws_dynamodb_table.detection_state.name
      KINESIS_STREAM       = aws_kinesis_stream.data_collection.name
      ENVIRONMENT          = var.environment
    }
  }

  tags = {
    Name        = "Data processor lambda"
    Environment = var.environment
  }
}