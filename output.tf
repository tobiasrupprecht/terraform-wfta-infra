output "instance_ip" {
  description = "The public ip of the database server for ssh access"
  value       = aws_instance.database_server.public_ip
}
output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "load_balancer_address" {
  description = "Public IP of the LoadBalancer service"
  value       = kubernetes_service.web_app_lb.status[0].load_balancer[0].ingress[0].ip
}