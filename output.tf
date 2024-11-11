output "instance_ip" {
  description = "The public ip of the database server for ssh access"
  value       = aws_instance.database_server.public_ip
}