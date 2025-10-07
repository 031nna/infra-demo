# Default values

variable "do_token" {
  description = "DigitalOcean API token"
}

variable "dhub_token" {
  description = "Dockerhub API token"
}

variable "dhub_user" {
  description = "Dockerhub User"
}

variable "cloudflare_token" {
  description = "Cloudflare API token"
}

variable "admin_user" {
  description = "Nizzles mail"
}

variable "droplet_image" {
  description = "Image identifier of the OS in DigitalOcean"
  default     = "ubuntu-20-04-x64"
}

variable "droplet_region" {
  description = "Droplet region identifier where the droplet will be created"
  default     = "sfo3"
}

# NB: For 30,000 users/day use the equivalent of s-4vcpu-8gb 
# or betterstill split into two servers (s-2vcpu-4gb x 2)  https://slugs.do-api.dev/
variable "droplet_size" {
  description = "Droplet size identifier"
  default     = "s-2vcpu-4gb" # basic server conf for dockerized laravel
}

variable "db_droplet_size" {
  description = "Droplet size identifier"
  default     = "s-1vcpu-1gb"  
}

variable "mail_droplet_size" {
  description = "Droplet size identifier"
  default     = "s-1vcpu-2gb"  # the recommended size is "s-2vcpu-4gb"s
}

variable "instance_count" {
    description = "number of running droplets"
    type = number
    default = 1 #2
}

variable "db_instance_count" {
    description = "number of running droplets"
    type = number
    default = 0
}

variable "mail_server_instance_count" {
    description = "number of running droplets"
    type = number
    default = 1
}

variable "staging_instance_count" {
    description = "number of running staging  instances"
    type = number
    default = 0
}

variable "app_domain_name" {
    description = "name of app domain"
    default = "03i.co"
}

variable "mailer_name" {
    description = "mail service subdomain"
    default = "mailer"
}

variable "chat_bot_name" {
    description = "chat service subdomain"
    default = "chat"
}

variable "test_domain_name" {
    description = "staging server subdomain"
    default = "staging"
}

variable "records" {
  type = list(object({
    value    = string
    priority = number
  }))

  default = [
    {
      value    = "ASPMX.L.GOOGLE.COM."
      priority = 1
    },
    {
      value    = "ALT1.ASPMX.L.GOOGLE.COM."
      priority = 5
    },
    {
      value    = "ALT2.ASPMX.L.GOOGLE.COM."
      priority = 5
    },
    {
      value    = "ALT3.ASPMX.L.GOOGLE.COM."
      priority = 10
    },
    {
      value    = "ALT4.ASPMX.L.GOOGLE.COM."
      priority = 10
    }
  ]
}

variable "cloudflare_account_type" {
    description = "Account type being used on cloudflare"
    type = string
    default = "free"
}

variable "cloudflare_account_id" {
    description = "Account id being used on cloudflare"
    type = string
    default = ""
}

variable "cloudflare_zone_id" {
    description = "Zone id being used on cloudflare"
    type = string
    default = ""
}

variable "aws_region" {
  description = "ec2 instance type"
  type = string
  default = "us-east-1"
}

variable "ami_id" {
    description = "ami image type eg ubuntu"
    type = string
    default = "ami-067cf009aedb2612d"  #"ami-0fc5d935ebf8bc3bc" # "t4g.small"  
}

variable "instance_type" {
    description = "instance type"
    type = string
    default = "t4g.small" #"t3.micro" #  "ami-067cf009aedb2612d" 
}

variable "private_key_path" {
  description = "The file path to the private SSH key used to access servers(EC2 instances/DO droplets)"
  type        = string
  default     = "~/.ssh/id_rsa" # Replace with the path to your private key
}

variable "aws_key_name" {
  description = "The name of the SSH key pair to use for EC2 instances"
  type        = string
  default     = "giggl-staging" # "03i-staging". Replace with your actual key pair name in AWS
}

variable "ebs_volume_size" {
  default = 20  # Set the new size (adjust as needed)
}
 