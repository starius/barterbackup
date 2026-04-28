#compdef bbd

autoload -U is-at-least

_bbd() {
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
'--local-addr=[local_addr is the local loopback address for the CLI gRPC service]:LOCAL_ADDR:_default' \
'--data-dir=[data_dir is the base directory for all daemon state]:DATA_DIR:_files' \
'--arti-config=[arti_config is one optional Arti client TOML file passed directly to embedded Arti]:ARTI_CONFIG:_files' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
}

(( $+functions[_bbd_commands] )) ||
_bbd_commands() {
    local commands; commands=()
    _describe -t commands 'bbd commands' commands "$@"
}

if [ "$funcstack[1]" = "_bbd" ]; then
    _bbd "$@"
else
    compdef _bbd bbd
fi
