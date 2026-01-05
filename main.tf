resource "aws_instance" "app_server" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"

  # VULNERABILITY: Hardcoded Access Key (Rule TF-002)
  provisioner "local-exec" {
    command = "echo AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\" > config"
  }
}

resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  # VULNERABILITY: Open Security Group (Rule TF-001)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VULNERABILITY: Hardcoded Private Key (Rule TF-003)
output "private_key" {
  value = "-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggVkAgEAAoIBAQD..."
}