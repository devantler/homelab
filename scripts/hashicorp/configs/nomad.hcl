datacenter = "dc1"
data_dir   = "/opt/nomad"
server {
  enabled          = true
  bootstrap_expect = 3
  server_join {
    retry_join = ["192.168.10.1", "192.168.10.2",  "192.168.10.3"]
  }
}
client {
  enabled = true
  server_join {
    retry_join = ["192.168.10.1", "192.168.10.2",  "192.168.10.3"]
  }
}
plugin "docker" {
  config {
    allow_privileged = true
    allow_caps       = ["audit_write", "chown", "dac_override", "fowner", "fsetid", "kill", "mknod", "net_bind_service", "setfcap", "setgid", "setpcap", "setuid", "sys_chroot", "net_admin", "sys_nice"]
    volumes {
      enabled = true
    }
  }
}
