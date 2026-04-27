complete -c bbd -l local-addr -d 'local_addr is the local loopback address for the CLI gRPC service' -r
complete -c bbd -l data-dir -d 'data_dir is the base directory for all daemon state' -r -F
complete -c bbd -l arti-config -d 'arti_config is one optional Arti TOML file for custom test networks' -r -F
complete -c bbd -l test-clock -d 'test_clock enables the hidden daemon test clock control RPCs'
complete -c bbd -l disable-maintenance -d 'disable_maintenance disables the background maintenance loop for tests'
complete -c bbd -s h -l help -d 'Print help'
