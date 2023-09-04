terraform {
  required_providers {
    mongodbatlas = {
      source  = "mongodb/mongodbatlas"
      version = "~> 1.11"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket    	   = "tf-test-bucket-source-test"
    key       	   = "tf-test-bucket-source-test.tfstate"
    region         = "us-west-2"
    encrypt        = true
    dynamodb_table = "tf-test-bucket-source-test_locks"
  }
}

provider "aws" {
  region = "us-west-1"
}
