terraform {
  required_providers {
    digitalocean = {
      source = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 3.0"  # Check for the latest version on Terraform Registry
    }
    aws = {
      source  = "hashicorp/aws"
    }
  }
}

provider "digitalocean" {
  token = var.do_token
}

provider "cloudflare" {
  email    = "${var.admin_user}@gmail.com" 
  api_key  = var.cloudflare_token 
}

provider "aws" {
    profile = "aws_staging"
    region  = var.aws_region
}

provider "external" {}

data "digitalocean_ssh_key" "terraform_ssh_key" {
  name = "MainKey"
}

data "external" "enable_brotli" {
  program = ["bash", "../bin/enable_brotli.sh"]

  query = {
    zone_id  = var.cloudflare_zone_id
    api_token = var.cloudflare_token
  }
}

resource "digitalocean_droplet" "web" {
  count = var.instance_count
  image = var.droplet_image
  name = "${var.app_domain_name}-appserver-0${count.index + 1}"
  region = var.droplet_region
  size = var.droplet_size
  monitoring         = true
  # private_networking = true
  ssh_keys = [
    data.digitalocean_ssh_key.terraform_ssh_key.id
  ]

  connection {
    host = self.ipv4_address
    user = "root"
    type = "ssh"
    private_key = file(var.private_key_path)
    timeout = "2m"
  }
}

resource "digitalocean_droplet" "database" {
  count = var.db_instance_count
  image = var.droplet_image 
  name = "${var.app_domain_name}-dbserver-0${count.index + 1}"
  region = var.droplet_region
  size = var.db_droplet_size
  # backups            = true
  monitoring = true
  # private_networking = true
  ssh_keys = [
    data.digitalocean_ssh_key.terraform_ssh_key.id
  ]
}

resource "digitalocean_droplet" "mail_server" {
  count = var.mail_server_instance_count
  image = var.droplet_image 
  name = "${var.app_domain_name}-mailserver"
  region = var.droplet_region
  size = var.mail_droplet_size
  # backups            = true
  monitoring = true
  # private_networking = true
  ssh_keys = [
    data.digitalocean_ssh_key.terraform_ssh_key.id
  ]
}

# Firewall
resource "digitalocean_firewall" "web" {
  name = "${var.app_domain_name}-only-allow-ssh-http-and-https"
  # droplet_ids = digitalocean_droplet.web.*.id
  droplet_ids = flatten([digitalocean_droplet.web.*.id, digitalocean_droplet.mail_server.*.id])

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "8282"
    source_addresses = ["0.0.0.0/0", "::/0"] 
    # @TODO; this source_addresses port range opens up to the whole, internet, 
    # might want to make it only for the host ip ['HOST_IP']
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Loki port rule
  inbound_rule {
    protocol         = "tcp"
    port_range       = "3100"
    source_addresses = ["0.0.0.0/0", "::/0"]
    # source_addresses = [
    #   "10.0.0.202",
    #   "2604:3d09:397f:ee00::688a",
    #   "34.160.175.123",
    #   "34.110.200.173",
    #   "34.117.128.64",
    #   "34.120.232.185",
    #   "35.182.185.137",
    #   "52.37.67.35",
    #   "3.131.178.9",
    #   "34.160.140.90",
    #   "18.184.215.172",
    #   "34.117.8.58",
    #   "34.117.203.175",
    #   "44.230.163.51",
    #   "52.189.70.155",
    #   "18.230.80.250",
    #   "34.160.8.201",
    #   "34.98.79.194",
    #   "13.237.86.14",
    #   "34.117.73.178",
    #   "18.182.219.129",
    #   "34.149.6.4",
    #   "52.58.110.222",
    #   "20.31.17.143",
    #   "34.120.86.103",
    #   "54.251.81.84",
    #   "34.160.251.167",
    #   "34.98.64.250",
    #   "16.170.105.167",
    #   "65.1.255.19",
    #   "3.134.31.160",
    #   "3.133.49.173",
    #   "3.75.6.195"
    # ]
  }

  # prometheus port rule
  inbound_rule {
    protocol         = "tcp"
    port_range       = "9090"
    source_addresses = ["0.0.0.0/0", "::/0"]
    # Consider restricting this to specific IPs or CIDR blocks if needed
    # source_addresses = [
    #   "10.0.0.202",
    #   "34.102.237.169",
    #   "18.139.155.52",
    #   "44.225.9.40",
    #   "34.102.140.197",
    #   "34.117.103.153",
    #   "34.117.118.190",
    #   "34.120.115.151",
    #   "34.96.126.110",
    #   "35.244.146.53",
    #   "3.69.125.237",
    #   "34.102.202.235",
    #   "34.149.133.46",
    #   "34.149.51.89",
    #   "34.160.168.21",
    #   "34.117.60.35",
    #   "34.111.185.173",
    #   "13.232.98.40",
    #   "34.117.67.173",
    #   "35.241.21.129",
    #   "34.120.72.239",
    #   "52.196.76.121",
    #   "20.31.17.143",
    #   "99.79.11.143",
    #   "16.170.185.60",
    #   "3.139.147.53",
    #   "34.111.145.147",
    #   "35.201.117.100",
    #   "34.117.7.29",
    #   "34.111.127.201",
    #   "52.189.70.155",
    #   "3.78.180.19",
    #   "54.252.28.31",
    #   "34.120.224.248",
    #   "3.22.86.39",
    #   "34.149.19.234",
    #   "177.71.166.12"
    # ]
  }

  inbound_rule {
    protocol         = "icmp"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "digitalocean_domain" "default" {
   name = var.app_domain_name
}

resource "digitalocean_record" "CNAME-www" {
  domain = digitalocean_domain.default.name
  type = "CNAME"
  name = "www"
  value = "@"
}

# lets encrypt cert
// fix this ok
resource "digitalocean_certificate" "cert" {
  name    = "${var.app_domain_name}-cert" 
  type    = "lets_encrypt"
  domains = [var.app_domain_name]
}

resource "digitalocean_loadbalancer" "web-lb" {
  name = "${var.app_domain_name}-web-lb"
  region = var.droplet_region

  forwarding_rule {
    entry_port = 80
    entry_protocol = "http"
    target_port = 8282 # switch to 80 to foward to cloudflare, 8282 if using servers lb without cloudflare 
    target_protocol = "http"
  }

  forwarding_rule {
    entry_port       = 443
    entry_protocol   = "https"
    target_port      = 8282
    target_protocol  = "https"
    # certificate_name = digitalocean_certificate.cert.name
    tls_passthrough = true # Terminate TLS on backend
  }

  healthcheck {
    port     = 443
    protocol = "https"
    path     = "/"
  }

  # healthcheck {
  #   port     = 80
  #   protocol = "http"
  #   path     = "/"
  # }
 

  droplet_ids = digitalocean_droplet.web.*.id
}

resource "digitalocean_firewall" "ssh-icmp-and-outbound" {
  name = "${var.app_domain_name}-allow-ssh-and-icmp"
  droplet_ids = flatten([digitalocean_droplet.web.*.id, digitalocean_droplet.database.*.id, digitalocean_droplet.mail_server.*.id])

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "icmp"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "digitalocean_firewall" "http-https" {
  name = "${var.app_domain_name}-allow-http-and-https"
  droplet_ids = flatten([digitalocean_droplet.web.*.id, digitalocean_droplet.mail_server.*.id])

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
    source_load_balancer_uids = [digitalocean_loadbalancer.web-lb.id]
  }

  inbound_rule {
    protocol                  = "tcp"
    port_range                = "80"
    source_load_balancer_uids = [digitalocean_loadbalancer.web-lb.id]
  }

  inbound_rule {
    protocol                  = "tcp"
    port_range                = "8282"
    source_load_balancer_uids = [digitalocean_loadbalancer.web-lb.id]
  }

  inbound_rule {
    protocol                  = "tcp"
    port_range                = "443"
    source_load_balancer_uids = [digitalocean_loadbalancer.web-lb.id]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "digitalocean_firewall" "mysql" {
  name = "${var.app_domain_name}-allow-mysql-traffic-from-webservers"
  droplet_ids = flatten([digitalocean_droplet.database.*.id])

  inbound_rule {
    protocol           = "tcp"
    port_range         = "3306"
    source_droplet_ids = flatten([digitalocean_droplet.web.*.id, digitalocean_droplet.mail_server.*.id])
  }

  inbound_rule {
    protocol           = "tcp"
    port_range         = "6379"
    source_droplet_ids = flatten([digitalocean_droplet.web.*.id, digitalocean_droplet.mail_server.*.id])
  }
}

resource "cloudflare_page_rule" "cache_static_content" {
  zone_id = var.cloudflare_zone_id 
  target  = "${digitalocean_domain.default.name}/*.(jpg|jpeg|png|gif|svg|webp)"
  priority = 1
  actions {
    cache_level = "cache_everything"
    edge_cache_ttl = 604800
    explicit_cache_control = "on"
  }
}

resource "cloudflare_page_rule" "bypass_cache" {
  zone_id = var.cloudflare_zone_id
  target  = "${digitalocean_domain.default.name}/*"
  priority = 2
  actions {
    # browser_cache_ttl = 0 # Respect Existing Headers
    # the REMEMBERME cookie is stored for logged in users
    # bypass_cache_on_cookie  = "REMEMBERME" # cookie name to conditionally bypass cache the page
    cache_level = "bypass" # This disables caching for all resources matched by this rule
    explicit_cache_control = "on"
    # waf = "on"
  }
}

# NB: works but caches userdetails as well from the browser 
resource "cloudflare_page_rule" "cache_services" {
  zone_id = var.cloudflare_zone_id 
  target  = "${digitalocean_domain.default.name}/service/*"
  priority = 3
  actions {
    cache_level = "cache_everything"
    # bypass_cache_on_cookie  = "REMEMBERME" # available in paid plan i believe
    explicit_cache_control = "on"
    # edge_cache_ttl = 7200
  }
}

resource "cloudflare_record" "mailer_A" {
  count  = length(digitalocean_droplet.mail_server) > 0 ? 1 : 0
  zone_id = var.cloudflare_zone_id 
  name    = "${var.mailer_name}.${var.app_domain_name}"
  value   = digitalocean_droplet.mail_server[0].ipv4_address
  type    = "A"
  ttl     = 1
  proxied = false  # disables Cloudflare proxying
}

resource "cloudflare_record" "chat_CNAME" {
  zone_id = var.cloudflare_zone_id 
  name    = "${var.chat_bot_name}.${var.app_domain_name}"
  value   = "faas-nyc1-2ef2e6cc.doserverless.co"
  type    = "CNAME"
  ttl     = 1
  proxied = false  # disables Cloudflare proxying
}

resource "cloudflare_worker_script" "chat_redirect" {
  account_id = var.cloudflare_account_id
  name       = "chat-redirect"
  content = <<EOT
addEventListener("fetch", event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const url = new URL(request.url);
    
    // Ensure that we properly append the path to the DigitalOcean function
    const targetUrl = "https://faas-nyc1-2ef2e6cc.doserverless.co/api/v1/web/fn-ac95261e-ae5c-4750-a38b-0feedf8115db/public/chat" + url.pathname + url.search;

    console.log("Incoming request to:", request.url);
    console.log("Forwarding to:", targetUrl);

    return fetch(targetUrl, {
        method: request.method,
        headers: request.headers
    });
}

EOT
}

resource "cloudflare_worker_route" "chat_redirect_route" {
  # account_id  = var.cloudflare_account_id  # Add this line
  zone_id     = var.cloudflare_zone_id
  pattern     = "${var.chat_bot_name}.${var.app_domain_name}/api/email/oauth2callback*"
  script_name = cloudflare_worker_script.chat_redirect.name
}

# resource "cloudflare_page_rule" "well_known" {
#   zone_id = var.cloudflare_zone_id 
#   target  = "https://${var.app_domain_name}/.well-known/*"  # Ensure the URL uses the protocol
#   actions {
#     cache_level = "bypass"
#     ssl         = "off"
#   }
# }

resource "cloudflare_record" "mailer_www_A" {
  count  = length(digitalocean_droplet.mail_server) > 0 ? 1 : 0
  zone_id = var.cloudflare_zone_id 
  name    = "www.${var.mailer_name}.${var.app_domain_name}"
  value   = digitalocean_droplet.mail_server[0].ipv4_address
  type    = "A"
  ttl     = 1
  proxied = false  # disables Cloudflare proxying
}

resource "cloudflare_zone_settings_override" "performance" {
  zone_id = var.cloudflare_zone_id
  settings {
    # Minification settings
    minify {
      css  = "on"
      js   = "on"
      html = "on"
    }

    # Caching strategy: Basic caching with optimized rules
    cache_level = "basic"
    browser_cache_ttl = 0  # Cache for 1 hour

    # Enabling automatic HTTPS rewrites for secure connections
    automatic_https_rewrites = "on"

    # Web Application Firewall (WAF) for added security
    waf = "on"

    # Enabling security features
    security_level = "high" # This provides a stronger security stance
    opportunistic_encryption = "on" # Encrypting traffic even if HTTPS is not enforced

    # HTTP/2 and HTTP/3 for better performance and low latency
    http2 = "on"
    http3 = "on"

    # TLS Settings: TLS 1.3 for better security
    tls_1_3 = "on"

    # Always Use HTTPS for automatic redirection to HTTPS
    always_use_https = "on"

    # Brotli compression for improved content delivery
    brotli = "on"

    # Enabling security headers
    security_header {
      enabled = true
      preload = true
      max_age = 31536000  # Cache security headers for 1 year
      include_subdomains = true
      nosniff = true
    }

    # Enable Polish (lossless image compression), if you serve images
    polish = "lossless"

    # Universal SSL for HTTPS support
    universal_ssl = "on"
    
    # Disable Mirage (since it is read-only and you are not using it)
    # mirage = "on"  # REMOVED

    # WebP support for image optimization
    webp = "on"

    # Additional performance tweaks
    origin_error_page_pass_thru = "on"  # Allow error pages to pass through
    # prefetch_preload = "on"  # Enable resource prefetching
  }
}

# Null resource to purge cache
resource "null_resource" "purge_cache" {
  provisioner "local-exec" {
    command = <<EOT
      curl -X POST "https://api.cloudflare.com/client/v4/zones/${var.cloudflare_zone_id}/purge_cache" \
      -H "Authorization: Bearer ${var.cloudflare_token}" \
      -H "Content-Type: application/json" \
      --data '{"purge_everything":true}'
    EOT
  }

  # Triggers cache purge whenever DNS records change
  triggers = {
    change = "${cloudflare_record.www.id}-${cloudflare_record.root_domain.id}"
  }
}

# MX Records for Gmail
resource "cloudflare_record" "mx_gmail" {
  count     = length(var.records)
  zone_id   = var.cloudflare_zone_id
  name      = "@"
  value     = var.records[count.index].value
  type      = "MX"
  priority  = var.records[count.index].priority
  ttl       = 3600
}

resource "cloudflare_record" "mx_mail" {
  zone_id   = var.cloudflare_zone_id
  name   = "mail"
  type   = "MX"
  value  = "feedback-smtp.us-east-1.amazonses.com."
  ttl    = 3600
  priority = 10
}

# Google DKIM CNAME Records
resource "cloudflare_record" "google_workspace_dkim" {
  zone_id = var.cloudflare_zone_id
  name    = "google._domainkey" # TXT record name provided by Google Workspace
  value   = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoP8B3f8AbBZxS1l0G6ViziSetZGTX/HJoCLENhHXmLK84lxMxCnh+KFDC1PFBhXGA+jcE3WuNsjUbCJB1nfh4H6txYi9XczbDYLS60/nqKXetXYLAZoN/SRnJxq5RWst8Mbn54VC5LdhNnE8dULjT6TAIfKFGGModGXYYjOrzx9FvJXlSeuR4V+IfB6MVEjq1gGmr2RgU4C3X05HWXyiVl5zfTqjFLkdpBK1CIVZENeFyyc7kPTf7+LV4yamaquYArhsXQC/SsIwYBiplG2w6acmeAlgxVKz8CMqAecqzNwCOguyyPkDqLXdjtBqCdmlM6W+TfmIDMmEcs3AuprOQIDAQAB." # TXT record value provided by Google Workspace
  type    = "TXT"
  ttl     = 3600
}

# Amazon SES DKIM CNAME Records
resource "cloudflare_record" "amazon_ses_dkim" {
  for_each = {
    "ydx37siibayvm7k5dt2sucl6c4hw5nrs._domainkey" = "ydx37siibayvm7k5dt2sucl6c4hw5nrs.dkim.amazonses.com."
    "547j3imgdfau43hgv4xa7jrnokdj5rpx._domainkey" = "547j3imgdfau43hgv4xa7jrnokdj5rpx.dkim.amazonses.com."
    "eivqgmhefggt6piaptfwuivfcry64njl._domainkey" = "eivqgmhefggt6piaptfwuivfcry64njl.dkim.amazonses.com."
  }

  zone_id = var.cloudflare_zone_id
  name    = each.key
  value   = each.value
  type    = "CNAME"
  ttl     = 3600
}

# Amazon SES DKIM CNAME Records for mailer
resource "cloudflare_record" "amazon_ses_dkim_mailer" {
  for_each = {
    "uyt5z36txmwckdoo7dxdek3hcegqoccd._domainkey" = "uyt5z36txmwckdoo7dxdek3hcegqoccd.dkim.amazonses.com."
    "wxfgbachzll6oz4gpnrmm6g6sh46upuj._domainkey" = "wxfgbachzll6oz4gpnrmm6g6sh46upuj.dkim.amazonses.com."
    "jkqi6qehl3md4mlgk4pfvg4ncrsqdcty._domainkey" = "jkqi6qehl3md4mlgk4pfvg4ncrsqdcty.dkim.amazonses.com."
  }

  zone_id = var.cloudflare_zone_id
  name    = "${each.key}.${var.mailer_name}.${var.app_domain_name}"
  value   = each.value
  type    = "CNAME"
  ttl     = 3600
}

# SPF TXT Record
resource "cloudflare_record" "txt_spf" {
  zone_id = var.cloudflare_zone_id
  name    = "@"
  value   = "v=spf1 include:amazonses.com include:_spf.google.com ~all"
  type    = "TXT"
  ttl     = 3600
}
 

# SPF TXT Record for mailer.giggl
resource "cloudflare_record" "spf_mailer" {
  zone_id = var.cloudflare_zone_id
  name   = var.mailer_name
  type   = "TXT"
  value  = "v=spf1 include:amazonses.com include:_spf.google.com ~all"
  ttl    = 3600
}

# DMARC TXT Record for mailer.giggl
resource "cloudflare_record" "dmarc_mailer" {
  zone_id = var.cloudflare_zone_id
  name   = "_dmarc.${var.mailer_name}"
  type   = "TXT"
  value  = "v=DMARC1; p=quarantine; rua=mailto:bounces@03i.co; ruf=mailto:bounces@03i.co; sp=quarantine; aspf=r;"
  ttl    = 3600
}
 
resource "cloudflare_record" "root_domain" {
  zone_id = var.cloudflare_zone_id
  name    = "@"
  value   = digitalocean_loadbalancer.web-lb.ip
  type    = "A"
  ttl     = 1
  proxied = true
}

# CNAME Record for www subdomain
resource "cloudflare_record" "www" {
  zone_id = var.cloudflare_zone_id
  name    = "www"
  value   = "@"
  type    = "CNAME"
  ttl     = 1
  proxied = true
}

# Google Site Verification
resource "cloudflare_record" "google_site_verification" {
  zone_id = var.cloudflare_zone_id
  name    = "@"
  value   = "google-site-verification=dxUdOPWZieH8on-XnKVN8LeBYKp3L99_kvQXxRtat1I"
  type    = "TXT"
  ttl     = 3600
}

# add google verification code, for google search console
resource "cloudflare_record" "google_search_verification" {
  zone_id = var.cloudflare_zone_id
  type   = "TXT"
  name   = "@"
  value  = "google-site-verification=v6XsvL44Rw_OVDH_c7R6UlTkFtblSDFTs13-kRc21io"
  ttl    = 3600
}

# Bing Site Verification
resource "cloudflare_record" "bing_verification" {
  zone_id = var.cloudflare_zone_id
  name    = "18f2984181ee1291d10512aa4be199b6"
  value   = "verify.bing.com."
  type    = "CNAME"
  ttl     = 3600
}

####################
#### aws configs 

resource "aws_instance" "staging" {
  count         = var.staging_instance_count
  ami           = var.ami_id #"ami-09e67e426f25ce0d7"  # Amazon Linux 2023 (Free Tier)
  instance_type = var.instance_type
  key_name      = var.aws_key_name
  security_groups = [aws_security_group.staging_sg.name]
  associate_public_ip_address = true

  root_block_device {
    volume_size = var.ebs_volume_size  # 10GB Free Tier
  }

  user_data = file("../bin/user_data.sh")  # Bootstrap script

  tags = {
    Name = "Giggl-Staging"
  }
}

resource "aws_security_group" "staging_sg" {
  name        = "staging-sg"
  description = "Allow HTTP, HTTPS, and SSH"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "cloudflare_record" "staging_dns" {
  count   = var.staging_instance_count  # This ensures the DNS records match the number of instances
  zone_id = var.cloudflare_zone_id
  name    = "staging-${count.index}"  # This ensures unique names for each record, like staging-0, staging-1, etc.
  type    = "A"
  value   = aws_instance.staging[count.index].public_ip  # Reference each instance's public IP
  ttl     = 300
  proxied = false
}