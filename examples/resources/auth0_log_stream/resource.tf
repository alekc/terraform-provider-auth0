resource "auth0_log_stream" "example" {
  name = "AWS Eventbridge"
  type = "eventbridge"
  status = "active"
  sink {
    aws_account_id = "my_account_id"
    aws_region = "us-east-2"
  }
}
