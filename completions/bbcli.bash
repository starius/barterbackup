_bbcli() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="bbcli"
                ;;
            bbcli,config)
                cmd="bbcli__subcmd__config"
                ;;
            bbcli,contract)
                cmd="bbcli__subcmd__contract"
                ;;
            bbcli,file)
                cmd="bbcli__subcmd__file"
                ;;
            bbcli,help)
                cmd="bbcli__subcmd__help"
                ;;
            bbcli,init)
                cmd="bbcli__subcmd__init"
                ;;
            bbcli,peer)
                cmd="bbcli__subcmd__peer"
                ;;
            bbcli,recovery)
                cmd="bbcli__subcmd__recovery"
                ;;
            bbcli,state)
                cmd="bbcli__subcmd__state"
                ;;
            bbcli,stop)
                cmd="bbcli__subcmd__stop"
                ;;
            bbcli,unlock)
                cmd="bbcli__subcmd__unlock"
                ;;
            bbcli__subcmd__config,get)
                cmd="bbcli__subcmd__config__subcmd__get"
                ;;
            bbcli__subcmd__config,help)
                cmd="bbcli__subcmd__config__subcmd__help"
                ;;
            bbcli__subcmd__config,set)
                cmd="bbcli__subcmd__config__subcmd__set"
                ;;
            bbcli__subcmd__config__subcmd__help,get)
                cmd="bbcli__subcmd__config__subcmd__help__subcmd__get"
                ;;
            bbcli__subcmd__config__subcmd__help,help)
                cmd="bbcli__subcmd__config__subcmd__help__subcmd__help"
                ;;
            bbcli__subcmd__config__subcmd__help,set)
                cmd="bbcli__subcmd__config__subcmd__help__subcmd__set"
                ;;
            bbcli__subcmd__contract,check)
                cmd="bbcli__subcmd__contract__subcmd__check"
                ;;
            bbcli__subcmd__contract,help)
                cmd="bbcli__subcmd__contract__subcmd__help"
                ;;
            bbcli__subcmd__contract,list)
                cmd="bbcli__subcmd__contract__subcmd__list"
                ;;
            bbcli__subcmd__contract,propose)
                cmd="bbcli__subcmd__contract__subcmd__propose"
                ;;
            bbcli__subcmd__contract__subcmd__help,check)
                cmd="bbcli__subcmd__contract__subcmd__help__subcmd__check"
                ;;
            bbcli__subcmd__contract__subcmd__help,help)
                cmd="bbcli__subcmd__contract__subcmd__help__subcmd__help"
                ;;
            bbcli__subcmd__contract__subcmd__help,list)
                cmd="bbcli__subcmd__contract__subcmd__help__subcmd__list"
                ;;
            bbcli__subcmd__contract__subcmd__help,propose)
                cmd="bbcli__subcmd__contract__subcmd__help__subcmd__propose"
                ;;
            bbcli__subcmd__file,delete)
                cmd="bbcli__subcmd__file__subcmd__delete"
                ;;
            bbcli__subcmd__file,get)
                cmd="bbcli__subcmd__file__subcmd__get"
                ;;
            bbcli__subcmd__file,help)
                cmd="bbcli__subcmd__file__subcmd__help"
                ;;
            bbcli__subcmd__file,list)
                cmd="bbcli__subcmd__file__subcmd__list"
                ;;
            bbcli__subcmd__file,set)
                cmd="bbcli__subcmd__file__subcmd__set"
                ;;
            bbcli__subcmd__file__subcmd__help,delete)
                cmd="bbcli__subcmd__file__subcmd__help__subcmd__delete"
                ;;
            bbcli__subcmd__file__subcmd__help,get)
                cmd="bbcli__subcmd__file__subcmd__help__subcmd__get"
                ;;
            bbcli__subcmd__file__subcmd__help,help)
                cmd="bbcli__subcmd__file__subcmd__help__subcmd__help"
                ;;
            bbcli__subcmd__file__subcmd__help,list)
                cmd="bbcli__subcmd__file__subcmd__help__subcmd__list"
                ;;
            bbcli__subcmd__file__subcmd__help,set)
                cmd="bbcli__subcmd__file__subcmd__help__subcmd__set"
                ;;
            bbcli__subcmd__help,config)
                cmd="bbcli__subcmd__help__subcmd__config"
                ;;
            bbcli__subcmd__help,contract)
                cmd="bbcli__subcmd__help__subcmd__contract"
                ;;
            bbcli__subcmd__help,file)
                cmd="bbcli__subcmd__help__subcmd__file"
                ;;
            bbcli__subcmd__help,help)
                cmd="bbcli__subcmd__help__subcmd__help"
                ;;
            bbcli__subcmd__help,init)
                cmd="bbcli__subcmd__help__subcmd__init"
                ;;
            bbcli__subcmd__help,peer)
                cmd="bbcli__subcmd__help__subcmd__peer"
                ;;
            bbcli__subcmd__help,recovery)
                cmd="bbcli__subcmd__help__subcmd__recovery"
                ;;
            bbcli__subcmd__help,state)
                cmd="bbcli__subcmd__help__subcmd__state"
                ;;
            bbcli__subcmd__help,stop)
                cmd="bbcli__subcmd__help__subcmd__stop"
                ;;
            bbcli__subcmd__help,unlock)
                cmd="bbcli__subcmd__help__subcmd__unlock"
                ;;
            bbcli__subcmd__help__subcmd__config,get)
                cmd="bbcli__subcmd__help__subcmd__config__subcmd__get"
                ;;
            bbcli__subcmd__help__subcmd__config,set)
                cmd="bbcli__subcmd__help__subcmd__config__subcmd__set"
                ;;
            bbcli__subcmd__help__subcmd__contract,check)
                cmd="bbcli__subcmd__help__subcmd__contract__subcmd__check"
                ;;
            bbcli__subcmd__help__subcmd__contract,list)
                cmd="bbcli__subcmd__help__subcmd__contract__subcmd__list"
                ;;
            bbcli__subcmd__help__subcmd__contract,propose)
                cmd="bbcli__subcmd__help__subcmd__contract__subcmd__propose"
                ;;
            bbcli__subcmd__help__subcmd__file,delete)
                cmd="bbcli__subcmd__help__subcmd__file__subcmd__delete"
                ;;
            bbcli__subcmd__help__subcmd__file,get)
                cmd="bbcli__subcmd__help__subcmd__file__subcmd__get"
                ;;
            bbcli__subcmd__help__subcmd__file,list)
                cmd="bbcli__subcmd__help__subcmd__file__subcmd__list"
                ;;
            bbcli__subcmd__help__subcmd__file,set)
                cmd="bbcli__subcmd__help__subcmd__file__subcmd__set"
                ;;
            bbcli__subcmd__help__subcmd__peer,connect)
                cmd="bbcli__subcmd__help__subcmd__peer__subcmd__connect"
                ;;
            bbcli__subcmd__help__subcmd__peer,export-built-in)
                cmd="bbcli__subcmd__help__subcmd__peer__subcmd__export__subcmd__built__subcmd__in"
                ;;
            bbcli__subcmd__help__subcmd__peer,list)
                cmd="bbcli__subcmd__help__subcmd__peer__subcmd__list"
                ;;
            bbcli__subcmd__help__subcmd__peer,pin)
                cmd="bbcli__subcmd__help__subcmd__peer__subcmd__pin"
                ;;
            bbcli__subcmd__help__subcmd__peer,unpin)
                cmd="bbcli__subcmd__help__subcmd__peer__subcmd__unpin"
                ;;
            bbcli__subcmd__help__subcmd__recovery,checkout)
                cmd="bbcli__subcmd__help__subcmd__recovery__subcmd__checkout"
                ;;
            bbcli__subcmd__help__subcmd__recovery,conflicts)
                cmd="bbcli__subcmd__help__subcmd__recovery__subcmd__conflicts"
                ;;
            bbcli__subcmd__help__subcmd__recovery,resolve)
                cmd="bbcli__subcmd__help__subcmd__recovery__subcmd__resolve"
                ;;
            bbcli__subcmd__help__subcmd__recovery,run)
                cmd="bbcli__subcmd__help__subcmd__recovery__subcmd__run"
                ;;
            bbcli__subcmd__peer,connect)
                cmd="bbcli__subcmd__peer__subcmd__connect"
                ;;
            bbcli__subcmd__peer,export-built-in)
                cmd="bbcli__subcmd__peer__subcmd__export__subcmd__built__subcmd__in"
                ;;
            bbcli__subcmd__peer,help)
                cmd="bbcli__subcmd__peer__subcmd__help"
                ;;
            bbcli__subcmd__peer,list)
                cmd="bbcli__subcmd__peer__subcmd__list"
                ;;
            bbcli__subcmd__peer,pin)
                cmd="bbcli__subcmd__peer__subcmd__pin"
                ;;
            bbcli__subcmd__peer,unpin)
                cmd="bbcli__subcmd__peer__subcmd__unpin"
                ;;
            bbcli__subcmd__peer__subcmd__help,connect)
                cmd="bbcli__subcmd__peer__subcmd__help__subcmd__connect"
                ;;
            bbcli__subcmd__peer__subcmd__help,export-built-in)
                cmd="bbcli__subcmd__peer__subcmd__help__subcmd__export__subcmd__built__subcmd__in"
                ;;
            bbcli__subcmd__peer__subcmd__help,help)
                cmd="bbcli__subcmd__peer__subcmd__help__subcmd__help"
                ;;
            bbcli__subcmd__peer__subcmd__help,list)
                cmd="bbcli__subcmd__peer__subcmd__help__subcmd__list"
                ;;
            bbcli__subcmd__peer__subcmd__help,pin)
                cmd="bbcli__subcmd__peer__subcmd__help__subcmd__pin"
                ;;
            bbcli__subcmd__peer__subcmd__help,unpin)
                cmd="bbcli__subcmd__peer__subcmd__help__subcmd__unpin"
                ;;
            bbcli__subcmd__recovery,checkout)
                cmd="bbcli__subcmd__recovery__subcmd__checkout"
                ;;
            bbcli__subcmd__recovery,conflicts)
                cmd="bbcli__subcmd__recovery__subcmd__conflicts"
                ;;
            bbcli__subcmd__recovery,help)
                cmd="bbcli__subcmd__recovery__subcmd__help"
                ;;
            bbcli__subcmd__recovery,resolve)
                cmd="bbcli__subcmd__recovery__subcmd__resolve"
                ;;
            bbcli__subcmd__recovery,run)
                cmd="bbcli__subcmd__recovery__subcmd__run"
                ;;
            bbcli__subcmd__recovery__subcmd__help,checkout)
                cmd="bbcli__subcmd__recovery__subcmd__help__subcmd__checkout"
                ;;
            bbcli__subcmd__recovery__subcmd__help,conflicts)
                cmd="bbcli__subcmd__recovery__subcmd__help__subcmd__conflicts"
                ;;
            bbcli__subcmd__recovery__subcmd__help,help)
                cmd="bbcli__subcmd__recovery__subcmd__help__subcmd__help"
                ;;
            bbcli__subcmd__recovery__subcmd__help,resolve)
                cmd="bbcli__subcmd__recovery__subcmd__help__subcmd__resolve"
                ;;
            bbcli__subcmd__recovery__subcmd__help,run)
                cmd="bbcli__subcmd__recovery__subcmd__help__subcmd__run"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        bbcli)
            opts="-h --local-addr --data-dir --help state init unlock stop peer file contract recovery config help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --local-addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --data-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__config)
            opts="-h --help get set help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__config__subcmd__get)
            opts="-h --peers-storage --min-replicas --resource-policy --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__config__subcmd__help)
            opts="get set help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__config__subcmd__help__subcmd__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__config__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__config__subcmd__help__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__config__subcmd__set)
            opts="-h --peers-storage --min-replicas --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --peers-storage)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-replicas)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__contract)
            opts="-h --help list propose check help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__contract__subcmd__check)
            opts="-h --help <ONION_SERVICE_ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__contract__subcmd__help)
            opts="list propose check help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__contract__subcmd__help__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__contract__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__contract__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__contract__subcmd__help__subcmd__propose)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__contract__subcmd__list)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__contract__subcmd__propose)
            opts="-h --help <ONION_SERVICE_ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file)
            opts="-h --help list set get delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file__subcmd__delete)
            opts="-h --help <NAME>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file__subcmd__get)
            opts="-h --help <NAME> [OUT]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file__subcmd__help)
            opts="list set get delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file__subcmd__help__subcmd__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file__subcmd__help__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file__subcmd__list)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__file__subcmd__set)
            opts="-h --help <NAME> <PATH>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help)
            opts="state init unlock stop peer file contract recovery config help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__config)
            opts="get set"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__config__subcmd__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__config__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__contract)
            opts="list propose check"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__contract__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__contract__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__contract__subcmd__propose)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__file)
            opts="list set get delete"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__file__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__file__subcmd__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__file__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__file__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__peer)
            opts="connect pin unpin list export-built-in"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__peer__subcmd__connect)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__peer__subcmd__export__subcmd__built__subcmd__in)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__peer__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__peer__subcmd__pin)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__peer__subcmd__unpin)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__recovery)
            opts="run conflicts checkout resolve"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__recovery__subcmd__checkout)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__recovery__subcmd__conflicts)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__recovery__subcmd__resolve)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__recovery__subcmd__run)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__state)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__stop)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__help__subcmd__unlock)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__init)
            opts="-h --password-stdin --wait-seconds --help [PASSWORD]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --wait-seconds)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer)
            opts="-h --help connect pin unpin list export-built-in help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__connect)
            opts="-h --help <ONION_SERVICE_ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__export__subcmd__built__subcmd__in)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__help)
            opts="connect pin unpin list export-built-in help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__help__subcmd__connect)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__help__subcmd__export__subcmd__built__subcmd__in)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__help__subcmd__pin)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__help__subcmd__unpin)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__list)
            opts="-h --status --with-contract --without-contract --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --status)
                    COMPREPLY=($(compgen -W "connected online offline" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__pin)
            opts="-h --help <ONION_SERVICE_ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__peer__subcmd__unpin)
            opts="-h --help <ONION_SERVICE_ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery)
            opts="-h --help run conflicts checkout resolve help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery__subcmd__checkout)
            opts="-h --help <CONTENT_ID> <OUT_DIR>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery__subcmd__conflicts)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery__subcmd__help)
            opts="run conflicts checkout resolve help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery__subcmd__help__subcmd__checkout)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery__subcmd__help__subcmd__conflicts)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery__subcmd__help__subcmd__resolve)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery__subcmd__help__subcmd__run)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery__subcmd__resolve)
            opts="-h --help <CONTENT_ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__recovery__subcmd__run)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__state)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__stop)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bbcli__subcmd__unlock)
            opts="-h --password-stdin --wait-seconds --help [PASSWORD]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --wait-seconds)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _bbcli -o nosort -o bashdefault -o default bbcli
else
    complete -F _bbcli -o bashdefault -o default bbcli
fi
