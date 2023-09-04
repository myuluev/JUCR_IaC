1. Create terraform IAM role and secrets for access to AWS
2. Add variables AWS_ACCESS_KEY and AWS_SECRET_KEY to GitHub "Actions secrets and variables"
3. Add MongoDB credentials to GitHub "Actions secrets and variables"
- https://www.mongodb.com/developer/products/atlas/deploy-mongodb-atlas-terraform-aws/
4. Clone repository and run it with next commands:
- terraform init
- terraform plan
- terraform apply
or you can use it with GitHub Actions pipelines