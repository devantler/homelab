id = "adguardhome-volume"
name = "adguardhome-volume"
type = "csi"
plugin_id = "ceph-csi"

capability {
  access_mode = "single-node-writer"
  attachment_mode = "file-system"
}

secrets {
  adminID  = "admin"
  adminKey = "AQDZuO9isefKLBAA1lZQ9Ix3YR7BE21iAR/+9Q=="
}

parameters {
  clusterID = "8ac5dea8-d7d0-11ec-b09e-e45f01a7926b"
  fsName = "cephfs"
}