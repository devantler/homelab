id = "letsencrypt-volume"
name = "letsencrypt-volume"
type = "csi"
plugin_id = "ceph-csi"

capability {
  access_mode = "multi-node-multi-writer"
  attachment_mode = "file-system"
}

secrets {
  adminID  = "admin"
  adminKey = "AQD024ZiVBYJFxAAweH9j/+Rp1mZ79AgNDv2Zw=="
}

parameters {
  clusterID = "8ac5dea8-d7d0-11ec-b09e-e45f01a7926b"
  fsName = "cephfs"
}