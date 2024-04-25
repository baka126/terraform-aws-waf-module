module "alb" {
  # checkov:skip=CKV_TF_1: Ensure Terraform module sources use a commit hash
  source = "github.com/adexltd/terraform-aws-elb-module.git?ref=v4.0.0"

  name                       = "my-alb"
  load_balancer_type         = "application"
  vpc_id                     = aws_vpc.my_vpc.id
  subnets                    = [aws_subnet.subnet_1.id, aws_subnet.subnet_2.id]
  security_groups            = [aws_security_group.my_security_group.id]
  enable_deletion_protection = false

}
