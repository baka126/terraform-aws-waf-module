module "alb" {
  # checkov:skip=CKV_TF_1: Ensure Terraform module sources use a commit hash
  source = "github.com/adexltd/terraform-aws-elb-module.git?ref=v4.0.0"


  name = "my-alb"

  load_balancer_type = "application"

}
