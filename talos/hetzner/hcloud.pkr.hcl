packer {
  required_plugins {
    hcloud = {
      version = ">= 1.5.3"
      source  = "github.com/hetznercloud/hcloud"
    }
  }
}

locals {
  image = "media/talos-v1.7.6-arm64.raw.xz"
}

source "hcloud" "talos" {
  rescue       = "linux64"
  image        = "debian-12" #
  location     = "fsn1" # https://docs.hetzner.com/cloud/general/locations
  server_type  = "cax11" # https://docs.hetzner.com/cloud/servers/overview
  ssh_username = "root"

  snapshot_name = "Talos v1.7.6 (arm64)"

  server_name = "homelab-talos-1"
}

build {
  sources = ["source.hcloud.talos"]

  provisioner "file" {
    source = "${local.image}"
    destination = "/tmp/talos.raw.xz"
  }

  provisioner "shell" {
    inline = [
      "xz -d -c /tmp/talos.raw.xz | dd of=/dev/sda && sync",
    ]
  }
}
