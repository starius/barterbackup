complete -c bbd -l local-addr -d 'local_addr is the local loopback address for the CLI gRPC service' -r
complete -c bbd -l data-dir -d 'data_dir is the base directory for all daemon state' -r -F
complete -c bbd -l arti-config -d 'arti_config is one optional Arti client TOML file passed directly to embedded Arti' -r -F
complete -c bbd -s h -l help -d 'Print help'
complete -c bbd -s V -l version -d 'Print version'
