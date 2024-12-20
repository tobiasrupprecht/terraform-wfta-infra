variable "public_key" {
  type    = string
  default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDA6OadR6c1jx9zrJhPXBSJ4myqNxd3Q6Tqp2mOaDRQB0t6hIOoC5m1S6ifjFKZlroiL6sr3NoDXszOGKkrM8EG+sXrJeLU+Fp5oPUUZY9swDM4CaHOGDQjy0O3b6TkTABN+TycaFSXsVSdgMIdz00DQzd1vWAl2yfV0gcVnQ5riAUs39Chfre/nDVqf/3baHjmWL4VPJh3QUwkfwPqj+2uG8IowivoP+8WggPgi78AOV2k8Yl7DC9md1ndwGw+QrgDp6y0rtrbXa39bENRvxeuwzDqUK5IaQpMtnx5pve3Qe/2Hq1SAq03DgnwWkkK7XxYat8KNTwmCm4wc3AWQoNSNamuJTLtHzuQRMa35qtglRR0kY7+2v5bi8ESPvG+vV9bHJqmszMlwY1CRCWMeEnhfBsCm6I27NfF7rMHfoWIE/z69XXqrP+m/uCTUOHwtlTh6Dy782FBshAv51D58uhZXEN+uvZG0WH/LZLcrFpcPDiYXh41p3jCJvPo9vuSgEhQG9oLLWztOQO6tqe+FpiSXIZNZcqdhiIZRwOAIWxp5mQ70QU3b8l+PVJRyj1DprE9wIPjp1LzdlSidueV2KOZpUPPxWfTKAyWgITl5QfsdYL/5xWe6Kwot9PPhwbNOqpJ6JHSn6ZSomi8MjDCi9FSPh+8DxH1adXrNBiJg9snlw== tobias.rupprecht@tobias.rupprecht-F2Y7WWC2M1"
}
variable "private_key" {
  type = string
}
variable "region" {
  type    = string
  default = "us-west-2"
}
variable "user_arn" {
  type    = string
  default = "XYZ"
}

