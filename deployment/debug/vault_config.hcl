ui            = true
cluster_addr  = "https://127.0.0.1:8201"
api_addr      = "https://127.0.0.1:8200"
disable_mlock = true

storage "raft" {
  path = "/vault/data/vaultData"
  node_id = "node1"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable = "true"
}

