output "database_server_ip" {
  description = "The public ip of the database server for ssh access"
  value       = aws_instance.database_server.public_ip
}
output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ids attached to the cluster control plane"
  value       = module.eks.cluster_security_group_id
}

output "EKS_security_group_id" {
  description = "Security group ids attached to the cluster control plane"
  value       = aws_security_group.eks_sg.id 
}

output "region" {
  description = "AWS region"
  value       = var.region
}

output "cluster_name" {
  description = "Kubernetes Cluster Name"
  value       = module.eks.cluster_name
}

output "load_balancer_hostname" {
  value = kubernetes_service.web_app_lb.status.0.load_balancer.0.ingress.0.hostname
}