#compdef bbcli

autoload -U is-at-least

_bbcli() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'--local-addr=[local_addr is the local daemon endpoint]:LOCAL_ADDR:_default' \
'--data-dir=[data_dir is the base directory for daemon state and local CLI keys]:DATA_DIR:_files' \
'-h[Print help]' \
'--help[Print help]' \
":: :_bbcli_commands" \
"*::: :->bbcli" \
&& ret=0
    case $state in
    (bbcli)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-command-$line[1]:"
        case $line[1] in
            (state)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(init)
_arguments "${_arguments_options[@]}" : \
'--wait-seconds=[wait_seconds is how long to wait for daemon startup readiness]:WAIT_SECONDS:_default' \
'--password-stdin[password_stdin reads the main password from standard input]' \
'-h[Print help]' \
'--help[Print help]' \
'::password -- password is the inline main password or seed string:_default' \
&& ret=0
;;
(unlock)
_arguments "${_arguments_options[@]}" : \
'--wait-seconds=[wait_seconds is how long to wait for daemon startup readiness]:WAIT_SECONDS:_default' \
'--password-stdin[password_stdin reads the main password from standard input]' \
'-h[Print help]' \
'--help[Print help]' \
'::password -- password is the inline main password or seed string:_default' \
&& ret=0
;;
(stop)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(peer)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_bbcli__subcmd__peer_commands" \
"*::: :->peer" \
&& ret=0

    case $state in
    (peer)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-peer-command-$line[1]:"
        case $line[1] in
            (connect)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':onion_service_id -- onion_service_id is the peer onion service identifier:_default' \
&& ret=0
;;
(pin)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':onion_service_id -- onion_service_id is the peer onion service identifier:_default' \
&& ret=0
;;
(unpin)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':onion_service_id -- onion_service_id is the peer onion service identifier:_default' \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
'*--status=[status filters peers by current local transport state]:STATUS:((connected\:"Connected peers still have an open cached outbound client"
online\:"Online peers were last observed live but are not connected now"
offline\:"Offline peers were last observed unreachable or have never been seen live"))' \
'(--without-contract)--with-contract[with_contract keeps only peers with persisted contract state]' \
'(--with-contract)--without-contract[without_contract keeps only peers without persisted contract state]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(export-built-in)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__peer__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-peer-help-command-$line[1]:"
        case $line[1] in
            (connect)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(pin)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(unpin)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(export-built-in)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(file)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_bbcli__subcmd__file_commands" \
"*::: :->file" \
&& ret=0

    case $state in
    (file)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-file-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(set)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':name -- name is the stable file name inside the encrypted content set:_default' \
':path -- path is the plaintext file path to upload:_files' \
&& ret=0
;;
(get)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':name -- name is the stable file name inside the encrypted content set:_default' \
'::out -- out is the optional output path for the downloaded plaintext file:_files' \
&& ret=0
;;
(delete)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':name -- name is the stable file name inside the encrypted content set:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__file__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-file-help-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(set)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(get)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(contract)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_bbcli__subcmd__contract_commands" \
"*::: :->contract" \
&& ret=0

    case $state in
    (contract)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-contract-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(propose)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':onion_service_id -- onion_service_id is the peer onion service identifier:_default' \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':onion_service_id -- onion_service_id is the peer onion service identifier:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__contract__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-contract-help-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(propose)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(recovery)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_bbcli__subcmd__recovery_commands" \
"*::: :->recovery" \
&& ret=0

    case $state in
    (recovery)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-recovery-command-$line[1]:"
        case $line[1] in
            (run)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(conflicts)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(checkout)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':content_id -- content_id is the hex-encoded revision identifier:_default' \
':out_dir -- out_dir is the local directory that receives the plaintext files:_files' \
&& ret=0
;;
(resolve)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':content_id -- content_id is the hex-encoded revision identifier to keep active:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__recovery__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-recovery-help-command-$line[1]:"
        case $line[1] in
            (run)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(conflicts)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(checkout)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(resolve)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(config)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_bbcli__subcmd__config_commands" \
"*::: :->config" \
&& ret=0

    case $state in
    (config)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-config-command-$line[1]:"
        case $line[1] in
            (get)
_arguments "${_arguments_options[@]}" : \
'--peers-storage[peers_storage prints only the peer-storage budget field]' \
'--min-replicas[min_replicas prints only the minimum replica target field]' \
'--resource-policy[resource_policy prints only the current read-only peer runtime limits]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(set)
_arguments "${_arguments_options[@]}" : \
'--peers-storage=[peers_storage sets the total bytes allocated to peer storage]:PEERS_STORAGE:_default' \
'--min-replicas=[min_replicas sets the minimum replica target for our content]:MIN_REPLICAS:_default' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__config__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-config-help-command-$line[1]:"
        case $line[1] in
            (get)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(set)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-help-command-$line[1]:"
        case $line[1] in
            (state)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(init)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(unlock)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(stop)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(peer)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__help__subcmd__peer_commands" \
"*::: :->peer" \
&& ret=0

    case $state in
    (peer)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-help-peer-command-$line[1]:"
        case $line[1] in
            (connect)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(pin)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(unpin)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(export-built-in)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(file)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__help__subcmd__file_commands" \
"*::: :->file" \
&& ret=0

    case $state in
    (file)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-help-file-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(set)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(get)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(contract)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__help__subcmd__contract_commands" \
"*::: :->contract" \
&& ret=0

    case $state in
    (contract)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-help-contract-command-$line[1]:"
        case $line[1] in
            (list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(propose)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(recovery)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__help__subcmd__recovery_commands" \
"*::: :->recovery" \
&& ret=0

    case $state in
    (recovery)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-help-recovery-command-$line[1]:"
        case $line[1] in
            (run)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(conflicts)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(checkout)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(resolve)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(config)
_arguments "${_arguments_options[@]}" : \
":: :_bbcli__subcmd__help__subcmd__config_commands" \
"*::: :->config" \
&& ret=0

    case $state in
    (config)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:bbcli-help-config-command-$line[1]:"
        case $line[1] in
            (get)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(set)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
}

(( $+functions[_bbcli_commands] )) ||
_bbcli_commands() {
    local commands; commands=(
'state:Print daemon state' \
'init:Initialize daemon storage with the main password' \
'unlock:Send the main password to the daemon unlock path' \
'stop:Ask the daemon to shut down gracefully' \
'peer:Manage known peers' \
'file:Manage files in the latest encrypted content blob' \
'contract:Inspect and drive contracts with peers' \
'recovery:Run recovery and resolve divergent revisions' \
'config:Read or update daemon configuration' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__config_commands] )) ||
_bbcli__subcmd__config_commands() {
    local commands; commands=(
'get:Print the current configuration and derived storage usage data' \
'set:Update one or more configuration fields' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli config commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__config__subcmd__get_commands] )) ||
_bbcli__subcmd__config__subcmd__get_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli config get commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__config__subcmd__help_commands] )) ||
_bbcli__subcmd__config__subcmd__help_commands() {
    local commands; commands=(
'get:Print the current configuration and derived storage usage data' \
'set:Update one or more configuration fields' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli config help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__config__subcmd__help__subcmd__get_commands] )) ||
_bbcli__subcmd__config__subcmd__help__subcmd__get_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli config help get commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__config__subcmd__help__subcmd__help_commands] )) ||
_bbcli__subcmd__config__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli config help help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__config__subcmd__help__subcmd__set_commands] )) ||
_bbcli__subcmd__config__subcmd__help__subcmd__set_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli config help set commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__config__subcmd__set_commands] )) ||
_bbcli__subcmd__config__subcmd__set_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli config set commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__contract_commands] )) ||
_bbcli__subcmd__contract_commands() {
    local commands; commands=(
'list:Print current contract state for known peers' \
'propose:Form or renew a contract with a peer and print streamed updates' \
'check:Verify a peer contract and print streamed updates' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli contract commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__contract__subcmd__check_commands] )) ||
_bbcli__subcmd__contract__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli contract check commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__contract__subcmd__help_commands] )) ||
_bbcli__subcmd__contract__subcmd__help_commands() {
    local commands; commands=(
'list:Print current contract state for known peers' \
'propose:Form or renew a contract with a peer and print streamed updates' \
'check:Verify a peer contract and print streamed updates' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli contract help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__contract__subcmd__help__subcmd__check_commands] )) ||
_bbcli__subcmd__contract__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli contract help check commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__contract__subcmd__help__subcmd__help_commands] )) ||
_bbcli__subcmd__contract__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli contract help help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__contract__subcmd__help__subcmd__list_commands] )) ||
_bbcli__subcmd__contract__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli contract help list commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__contract__subcmd__help__subcmd__propose_commands] )) ||
_bbcli__subcmd__contract__subcmd__help__subcmd__propose_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli contract help propose commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__contract__subcmd__list_commands] )) ||
_bbcli__subcmd__contract__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli contract list commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__contract__subcmd__propose_commands] )) ||
_bbcli__subcmd__contract__subcmd__propose_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli contract propose commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file_commands] )) ||
_bbcli__subcmd__file_commands() {
    local commands; commands=(
'list:Print the names of all files in the latest encrypted content blob' \
'set:Add or replace a file in the latest encrypted content blob' \
'get:Download a file from the latest encrypted content blob' \
'delete:Delete a file from the latest encrypted content blob' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli file commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file__subcmd__delete_commands] )) ||
_bbcli__subcmd__file__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli file delete commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file__subcmd__get_commands] )) ||
_bbcli__subcmd__file__subcmd__get_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli file get commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file__subcmd__help_commands] )) ||
_bbcli__subcmd__file__subcmd__help_commands() {
    local commands; commands=(
'list:Print the names of all files in the latest encrypted content blob' \
'set:Add or replace a file in the latest encrypted content blob' \
'get:Download a file from the latest encrypted content blob' \
'delete:Delete a file from the latest encrypted content blob' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli file help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file__subcmd__help__subcmd__delete_commands] )) ||
_bbcli__subcmd__file__subcmd__help__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli file help delete commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file__subcmd__help__subcmd__get_commands] )) ||
_bbcli__subcmd__file__subcmd__help__subcmd__get_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli file help get commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file__subcmd__help__subcmd__help_commands] )) ||
_bbcli__subcmd__file__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli file help help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file__subcmd__help__subcmd__list_commands] )) ||
_bbcli__subcmd__file__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli file help list commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file__subcmd__help__subcmd__set_commands] )) ||
_bbcli__subcmd__file__subcmd__help__subcmd__set_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli file help set commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file__subcmd__list_commands] )) ||
_bbcli__subcmd__file__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli file list commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__file__subcmd__set_commands] )) ||
_bbcli__subcmd__file__subcmd__set_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli file set commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help_commands] )) ||
_bbcli__subcmd__help_commands() {
    local commands; commands=(
'state:Print daemon state' \
'init:Initialize daemon storage with the main password' \
'unlock:Send the main password to the daemon unlock path' \
'stop:Ask the daemon to shut down gracefully' \
'peer:Manage known peers' \
'file:Manage files in the latest encrypted content blob' \
'contract:Inspect and drive contracts with peers' \
'recovery:Run recovery and resolve divergent revisions' \
'config:Read or update daemon configuration' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__config_commands] )) ||
_bbcli__subcmd__help__subcmd__config_commands() {
    local commands; commands=(
'get:Print the current configuration and derived storage usage data' \
'set:Update one or more configuration fields' \
    )
    _describe -t commands 'bbcli help config commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__config__subcmd__get_commands] )) ||
_bbcli__subcmd__help__subcmd__config__subcmd__get_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help config get commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__config__subcmd__set_commands] )) ||
_bbcli__subcmd__help__subcmd__config__subcmd__set_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help config set commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__contract_commands] )) ||
_bbcli__subcmd__help__subcmd__contract_commands() {
    local commands; commands=(
'list:Print current contract state for known peers' \
'propose:Form or renew a contract with a peer and print streamed updates' \
'check:Verify a peer contract and print streamed updates' \
    )
    _describe -t commands 'bbcli help contract commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__contract__subcmd__check_commands] )) ||
_bbcli__subcmd__help__subcmd__contract__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help contract check commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__contract__subcmd__list_commands] )) ||
_bbcli__subcmd__help__subcmd__contract__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help contract list commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__contract__subcmd__propose_commands] )) ||
_bbcli__subcmd__help__subcmd__contract__subcmd__propose_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help contract propose commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__file_commands] )) ||
_bbcli__subcmd__help__subcmd__file_commands() {
    local commands; commands=(
'list:Print the names of all files in the latest encrypted content blob' \
'set:Add or replace a file in the latest encrypted content blob' \
'get:Download a file from the latest encrypted content blob' \
'delete:Delete a file from the latest encrypted content blob' \
    )
    _describe -t commands 'bbcli help file commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__file__subcmd__delete_commands] )) ||
_bbcli__subcmd__help__subcmd__file__subcmd__delete_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help file delete commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__file__subcmd__get_commands] )) ||
_bbcli__subcmd__help__subcmd__file__subcmd__get_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help file get commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__file__subcmd__list_commands] )) ||
_bbcli__subcmd__help__subcmd__file__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help file list commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__file__subcmd__set_commands] )) ||
_bbcli__subcmd__help__subcmd__file__subcmd__set_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help file set commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__help_commands] )) ||
_bbcli__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__init_commands] )) ||
_bbcli__subcmd__help__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help init commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__peer_commands] )) ||
_bbcli__subcmd__help__subcmd__peer_commands() {
    local commands; commands=(
'connect:Add a peer onion identifier to the daemon'\''s known peer list' \
'pin:Pin a tracked peer so local policy treats it as operator-protected' \
'unpin:Remove an existing operator pin from a tracked peer' \
'list:Print the daemon'\''s current peer inventory' \
'export-built-in:Print the Rust source file for the compiled built-in peer list' \
    )
    _describe -t commands 'bbcli help peer commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__peer__subcmd__connect_commands] )) ||
_bbcli__subcmd__help__subcmd__peer__subcmd__connect_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help peer connect commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__peer__subcmd__export-built-in_commands] )) ||
_bbcli__subcmd__help__subcmd__peer__subcmd__export-built-in_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help peer export-built-in commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__peer__subcmd__list_commands] )) ||
_bbcli__subcmd__help__subcmd__peer__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help peer list commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__peer__subcmd__pin_commands] )) ||
_bbcli__subcmd__help__subcmd__peer__subcmd__pin_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help peer pin commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__peer__subcmd__unpin_commands] )) ||
_bbcli__subcmd__help__subcmd__peer__subcmd__unpin_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help peer unpin commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__recovery_commands] )) ||
_bbcli__subcmd__help__subcmd__recovery_commands() {
    local commands; commands=(
'run:Recover the newest known local content version from peers' \
'conflicts:List unresolved and archived conflicting revisions' \
'checkout:Write one conflicting or archived revision to a local directory' \
'resolve:Choose the conflicting revision that should stay active' \
    )
    _describe -t commands 'bbcli help recovery commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__recovery__subcmd__checkout_commands] )) ||
_bbcli__subcmd__help__subcmd__recovery__subcmd__checkout_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help recovery checkout commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__recovery__subcmd__conflicts_commands] )) ||
_bbcli__subcmd__help__subcmd__recovery__subcmd__conflicts_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help recovery conflicts commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__recovery__subcmd__resolve_commands] )) ||
_bbcli__subcmd__help__subcmd__recovery__subcmd__resolve_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help recovery resolve commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__recovery__subcmd__run_commands] )) ||
_bbcli__subcmd__help__subcmd__recovery__subcmd__run_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help recovery run commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__state_commands] )) ||
_bbcli__subcmd__help__subcmd__state_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help state commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__stop_commands] )) ||
_bbcli__subcmd__help__subcmd__stop_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help stop commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__help__subcmd__unlock_commands] )) ||
_bbcli__subcmd__help__subcmd__unlock_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli help unlock commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__init_commands] )) ||
_bbcli__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli init commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer_commands] )) ||
_bbcli__subcmd__peer_commands() {
    local commands; commands=(
'connect:Add a peer onion identifier to the daemon'\''s known peer list' \
'pin:Pin a tracked peer so local policy treats it as operator-protected' \
'unpin:Remove an existing operator pin from a tracked peer' \
'list:Print the daemon'\''s current peer inventory' \
'export-built-in:Print the Rust source file for the compiled built-in peer list' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli peer commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__connect_commands] )) ||
_bbcli__subcmd__peer__subcmd__connect_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer connect commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__export-built-in_commands] )) ||
_bbcli__subcmd__peer__subcmd__export-built-in_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer export-built-in commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__help_commands] )) ||
_bbcli__subcmd__peer__subcmd__help_commands() {
    local commands; commands=(
'connect:Add a peer onion identifier to the daemon'\''s known peer list' \
'pin:Pin a tracked peer so local policy treats it as operator-protected' \
'unpin:Remove an existing operator pin from a tracked peer' \
'list:Print the daemon'\''s current peer inventory' \
'export-built-in:Print the Rust source file for the compiled built-in peer list' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli peer help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__help__subcmd__connect_commands] )) ||
_bbcli__subcmd__peer__subcmd__help__subcmd__connect_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer help connect commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__help__subcmd__export-built-in_commands] )) ||
_bbcli__subcmd__peer__subcmd__help__subcmd__export-built-in_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer help export-built-in commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__help__subcmd__help_commands] )) ||
_bbcli__subcmd__peer__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer help help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__help__subcmd__list_commands] )) ||
_bbcli__subcmd__peer__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer help list commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__help__subcmd__pin_commands] )) ||
_bbcli__subcmd__peer__subcmd__help__subcmd__pin_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer help pin commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__help__subcmd__unpin_commands] )) ||
_bbcli__subcmd__peer__subcmd__help__subcmd__unpin_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer help unpin commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__list_commands] )) ||
_bbcli__subcmd__peer__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer list commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__pin_commands] )) ||
_bbcli__subcmd__peer__subcmd__pin_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer pin commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__peer__subcmd__unpin_commands] )) ||
_bbcli__subcmd__peer__subcmd__unpin_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli peer unpin commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery_commands] )) ||
_bbcli__subcmd__recovery_commands() {
    local commands; commands=(
'run:Recover the newest known local content version from peers' \
'conflicts:List unresolved and archived conflicting revisions' \
'checkout:Write one conflicting or archived revision to a local directory' \
'resolve:Choose the conflicting revision that should stay active' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli recovery commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery__subcmd__checkout_commands] )) ||
_bbcli__subcmd__recovery__subcmd__checkout_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli recovery checkout commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery__subcmd__conflicts_commands] )) ||
_bbcli__subcmd__recovery__subcmd__conflicts_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli recovery conflicts commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery__subcmd__help_commands] )) ||
_bbcli__subcmd__recovery__subcmd__help_commands() {
    local commands; commands=(
'run:Recover the newest known local content version from peers' \
'conflicts:List unresolved and archived conflicting revisions' \
'checkout:Write one conflicting or archived revision to a local directory' \
'resolve:Choose the conflicting revision that should stay active' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'bbcli recovery help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery__subcmd__help__subcmd__checkout_commands] )) ||
_bbcli__subcmd__recovery__subcmd__help__subcmd__checkout_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli recovery help checkout commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery__subcmd__help__subcmd__conflicts_commands] )) ||
_bbcli__subcmd__recovery__subcmd__help__subcmd__conflicts_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli recovery help conflicts commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery__subcmd__help__subcmd__help_commands] )) ||
_bbcli__subcmd__recovery__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli recovery help help commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery__subcmd__help__subcmd__resolve_commands] )) ||
_bbcli__subcmd__recovery__subcmd__help__subcmd__resolve_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli recovery help resolve commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery__subcmd__help__subcmd__run_commands] )) ||
_bbcli__subcmd__recovery__subcmd__help__subcmd__run_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli recovery help run commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery__subcmd__resolve_commands] )) ||
_bbcli__subcmd__recovery__subcmd__resolve_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli recovery resolve commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__recovery__subcmd__run_commands] )) ||
_bbcli__subcmd__recovery__subcmd__run_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli recovery run commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__state_commands] )) ||
_bbcli__subcmd__state_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli state commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__stop_commands] )) ||
_bbcli__subcmd__stop_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli stop commands' commands "$@"
}
(( $+functions[_bbcli__subcmd__unlock_commands] )) ||
_bbcli__subcmd__unlock_commands() {
    local commands; commands=()
    _describe -t commands 'bbcli unlock commands' commands "$@"
}

if [ "$funcstack[1]" = "_bbcli" ]; then
    _bbcli "$@"
else
    compdef _bbcli bbcli
fi
