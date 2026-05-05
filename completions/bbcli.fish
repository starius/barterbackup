# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_bbcli_global_optspecs
	string join \n local-addr= data-dir= h/help V/version
end

function __fish_bbcli_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_bbcli_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_bbcli_using_subcommand
	set -l cmd (__fish_bbcli_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c bbcli -n "__fish_bbcli_needs_command" -l local-addr -d 'local_addr is the local daemon endpoint' -r
complete -c bbcli -n "__fish_bbcli_needs_command" -l data-dir -d 'data_dir is the base directory for daemon state and local CLI keys' -r -F
complete -c bbcli -n "__fish_bbcli_needs_command" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_needs_command" -s V -l version -d 'Print version'
complete -c bbcli -n "__fish_bbcli_needs_command" -f -a "state" -d 'Print daemon state'
complete -c bbcli -n "__fish_bbcli_needs_command" -f -a "init" -d 'Initialize daemon storage with the main password or complete one recovery-mode initialization'
complete -c bbcli -n "__fish_bbcli_needs_command" -f -a "unlock" -d 'Send the main password to the daemon unlock path'
complete -c bbcli -n "__fish_bbcli_needs_command" -f -a "stop" -d 'Ask the daemon to shut down gracefully'
complete -c bbcli -n "__fish_bbcli_needs_command" -f -a "peer" -d 'Manage known peers'
complete -c bbcli -n "__fish_bbcli_needs_command" -f -a "file" -d 'Manage files in the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_needs_command" -f -a "config" -d 'Read or update daemon configuration'
complete -c bbcli -n "__fish_bbcli_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bbcli -n "__fish_bbcli_using_subcommand state" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand init; and not __fish_seen_subcommand_from complete help" -l wait-seconds -d 'wait_seconds is how long to wait for daemon startup readiness' -r
complete -c bbcli -n "__fish_bbcli_using_subcommand init; and not __fish_seen_subcommand_from complete help" -l password-stdin -d 'password_stdin reads the main password from standard input'
complete -c bbcli -n "__fish_bbcli_using_subcommand init; and not __fish_seen_subcommand_from complete help" -l allow-weak-password -d 'allow_weak_password bypasses the local password-strength gate'
complete -c bbcli -n "__fish_bbcli_using_subcommand init; and not __fish_seen_subcommand_from complete help" -l recovery-mode -d 'recovery_mode blocks outgoing publication until recovery is finished'
complete -c bbcli -n "__fish_bbcli_using_subcommand init; and not __fish_seen_subcommand_from complete help" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand init; and not __fish_seen_subcommand_from complete help" -a "complete" -d 'Complete recovery-mode initialization and allow publication'
complete -c bbcli -n "__fish_bbcli_using_subcommand init; and not __fish_seen_subcommand_from complete help" -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bbcli -n "__fish_bbcli_using_subcommand init; and __fish_seen_subcommand_from complete" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand init; and __fish_seen_subcommand_from help" -f -a "complete" -d 'Complete recovery-mode initialization and allow publication'
complete -c bbcli -n "__fish_bbcli_using_subcommand init; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bbcli -n "__fish_bbcli_using_subcommand unlock" -l wait-seconds -d 'wait_seconds is how long to wait for daemon startup readiness' -r
complete -c bbcli -n "__fish_bbcli_using_subcommand unlock" -l password-stdin -d 'password_stdin reads the main password from standard input'
complete -c bbcli -n "__fish_bbcli_using_subcommand unlock" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand stop" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and not __fish_seen_subcommand_from connect pin unpin list check help" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and not __fish_seen_subcommand_from connect pin unpin list check help" -f -a "connect" -d 'Add a peer onion identifier to the daemon\'s known peer list'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and not __fish_seen_subcommand_from connect pin unpin list check help" -f -a "pin" -d 'Pin a tracked peer so local policy treats it as operator-protected'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and not __fish_seen_subcommand_from connect pin unpin list check help" -f -a "unpin" -d 'Remove an existing operator pin from a tracked peer'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and not __fish_seen_subcommand_from connect pin unpin list check help" -f -a "list" -d 'Print the daemon\'s current peer inventory'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and not __fish_seen_subcommand_from connect pin unpin list check help" -f -a "check" -d 'Check one peer\'s current copy of our latest local revision'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and not __fish_seen_subcommand_from connect pin unpin list check help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from connect" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from pin" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from unpin" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from list" -l status -d 'status filters peers by current local transport state' -r -f -a "connected\t'Connected peers still have an open cached outbound client'
online\t'Online peers were last observed live but are not connected now'
offline\t'Offline peers were last observed unreachable or have never been seen live'"
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from list" -l with-storage -d 'with_storage keeps only peers with persisted storage state'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from list" -l without-storage -d 'without_storage keeps only peers without persisted storage state'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from check" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "connect" -d 'Add a peer onion identifier to the daemon\'s known peer list'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "pin" -d 'Pin a tracked peer so local policy treats it as operator-protected'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "unpin" -d 'Remove an existing operator pin from a tracked peer'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "list" -d 'Print the daemon\'s current peer inventory'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "check" -d 'Check one peer\'s current copy of our latest local revision'
complete -c bbcli -n "__fish_bbcli_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and not __fish_seen_subcommand_from list set get delete help" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and not __fish_seen_subcommand_from list set get delete help" -f -a "list" -d 'Print the names of all files in the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and not __fish_seen_subcommand_from list set get delete help" -f -a "set" -d 'Add or replace a file in the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and not __fish_seen_subcommand_from list set get delete help" -f -a "get" -d 'Download a file from the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and not __fish_seen_subcommand_from list set get delete help" -f -a "delete" -d 'Delete a file from the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and not __fish_seen_subcommand_from list set get delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and __fish_seen_subcommand_from help" -f -a "list" -d 'Print the names of all files in the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and __fish_seen_subcommand_from help" -f -a "set" -d 'Add or replace a file in the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and __fish_seen_subcommand_from help" -f -a "get" -d 'Download a file from the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a file from the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand file; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and not __fish_seen_subcommand_from get set help" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and not __fish_seen_subcommand_from get set help" -f -a "get" -d 'Print the current configuration and derived storage usage data'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and not __fish_seen_subcommand_from get set help" -f -a "set" -d 'Update one or more configuration fields'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and not __fish_seen_subcommand_from get set help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and __fish_seen_subcommand_from get" -l peers-storage -d 'peers_storage prints only the peer-storage budget field'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and __fish_seen_subcommand_from get" -l min-replicas -d 'min_replicas prints only the minimum replica target field'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and __fish_seen_subcommand_from get" -l resource-policy -d 'resource_policy prints only the current read-only peer runtime limits'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and __fish_seen_subcommand_from set" -l peers-storage -d 'peers_storage sets the total bytes allocated to peer storage' -r
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and __fish_seen_subcommand_from set" -l min-replicas -d 'min_replicas sets the minimum replica target for our content' -r
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "get" -d 'Print the current configuration and derived storage usage data'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "set" -d 'Update one or more configuration fields'
complete -c bbcli -n "__fish_bbcli_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and not __fish_seen_subcommand_from state init unlock stop peer file config help" -f -a "state" -d 'Print daemon state'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and not __fish_seen_subcommand_from state init unlock stop peer file config help" -f -a "init" -d 'Initialize daemon storage with the main password or complete one recovery-mode initialization'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and not __fish_seen_subcommand_from state init unlock stop peer file config help" -f -a "unlock" -d 'Send the main password to the daemon unlock path'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and not __fish_seen_subcommand_from state init unlock stop peer file config help" -f -a "stop" -d 'Ask the daemon to shut down gracefully'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and not __fish_seen_subcommand_from state init unlock stop peer file config help" -f -a "peer" -d 'Manage known peers'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and not __fish_seen_subcommand_from state init unlock stop peer file config help" -f -a "file" -d 'Manage files in the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and not __fish_seen_subcommand_from state init unlock stop peer file config help" -f -a "config" -d 'Read or update daemon configuration'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and not __fish_seen_subcommand_from state init unlock stop peer file config help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from init" -f -a "complete" -d 'Complete recovery-mode initialization and allow publication'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "connect" -d 'Add a peer onion identifier to the daemon\'s known peer list'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "pin" -d 'Pin a tracked peer so local policy treats it as operator-protected'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "unpin" -d 'Remove an existing operator pin from a tracked peer'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "list" -d 'Print the daemon\'s current peer inventory'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "check" -d 'Check one peer\'s current copy of our latest local revision'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from file" -f -a "list" -d 'Print the names of all files in the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from file" -f -a "set" -d 'Add or replace a file in the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from file" -f -a "get" -d 'Download a file from the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from file" -f -a "delete" -d 'Delete a file from the latest encrypted content blob'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "get" -d 'Print the current configuration and derived storage usage data'
complete -c bbcli -n "__fish_bbcli_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "set" -d 'Update one or more configuration fields'
