
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'bbcli' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'bbcli'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-') -or
                $element.Value -eq $wordToComplete) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'bbcli' {
            [CompletionResult]::new('--local-addr', '--local-addr', [CompletionResultType]::ParameterName, 'local_addr is the local daemon endpoint')
            [CompletionResult]::new('--data-dir', '--data-dir', [CompletionResultType]::ParameterName, 'data_dir is the base directory for daemon state and local CLI keys')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('state', 'state', [CompletionResultType]::ParameterValue, 'Print daemon state')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize daemon storage with the main password or complete one recovery-mode initialization')
            [CompletionResult]::new('unlock', 'unlock', [CompletionResultType]::ParameterValue, 'Send the main password to the daemon unlock path')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Ask the daemon to shut down gracefully')
            [CompletionResult]::new('peer', 'peer', [CompletionResultType]::ParameterValue, 'Manage known peers')
            [CompletionResult]::new('file', 'file', [CompletionResultType]::ParameterValue, 'Manage files in the latest encrypted content blob')
            [CompletionResult]::new('config', 'config', [CompletionResultType]::ParameterValue, 'Read or update daemon configuration')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'bbcli;state' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;init' {
            [CompletionResult]::new('--wait-seconds', '--wait-seconds', [CompletionResultType]::ParameterName, 'wait_seconds is how long to wait for daemon startup readiness')
            [CompletionResult]::new('--password-stdin', '--password-stdin', [CompletionResultType]::ParameterName, 'password_stdin reads the main password from standard input')
            [CompletionResult]::new('--allow-weak-password', '--allow-weak-password', [CompletionResultType]::ParameterName, 'allow_weak_password bypasses the local password-strength gate')
            [CompletionResult]::new('--recovery-mode', '--recovery-mode', [CompletionResultType]::ParameterName, 'recovery_mode blocks outgoing publication until recovery is finished')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('complete', 'complete', [CompletionResultType]::ParameterValue, 'Complete recovery-mode initialization and allow publication')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'bbcli;init;complete' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;init;help' {
            [CompletionResult]::new('complete', 'complete', [CompletionResultType]::ParameterValue, 'Complete recovery-mode initialization and allow publication')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'bbcli;init;help;complete' {
            break
        }
        'bbcli;init;help;help' {
            break
        }
        'bbcli;unlock' {
            [CompletionResult]::new('--wait-seconds', '--wait-seconds', [CompletionResultType]::ParameterName, 'wait_seconds is how long to wait for daemon startup readiness')
            [CompletionResult]::new('--password-stdin', '--password-stdin', [CompletionResultType]::ParameterName, 'password_stdin reads the main password from standard input')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;stop' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;peer' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('connect', 'connect', [CompletionResultType]::ParameterValue, 'Add a peer onion identifier to the daemon''s known peer list')
            [CompletionResult]::new('pin', 'pin', [CompletionResultType]::ParameterValue, 'Pin a tracked peer so local policy treats it as operator-protected')
            [CompletionResult]::new('unpin', 'unpin', [CompletionResultType]::ParameterValue, 'Remove an existing operator pin from a tracked peer')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'Print the daemon''s current peer inventory')
            [CompletionResult]::new('check', 'check', [CompletionResultType]::ParameterValue, 'Check one peer''s current copy of our latest local revision')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'bbcli;peer;connect' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;peer;pin' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;peer;unpin' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;peer;list' {
            [CompletionResult]::new('--status', '--status', [CompletionResultType]::ParameterName, 'status filters peers by current local transport state')
            [CompletionResult]::new('--with-storage', '--with-storage', [CompletionResultType]::ParameterName, 'with_storage keeps only peers with persisted storage state')
            [CompletionResult]::new('--without-storage', '--without-storage', [CompletionResultType]::ParameterName, 'without_storage keeps only peers without persisted storage state')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            break
        }
        'bbcli;peer;check' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;peer;help' {
            [CompletionResult]::new('connect', 'connect', [CompletionResultType]::ParameterValue, 'Add a peer onion identifier to the daemon''s known peer list')
            [CompletionResult]::new('pin', 'pin', [CompletionResultType]::ParameterValue, 'Pin a tracked peer so local policy treats it as operator-protected')
            [CompletionResult]::new('unpin', 'unpin', [CompletionResultType]::ParameterValue, 'Remove an existing operator pin from a tracked peer')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'Print the daemon''s current peer inventory')
            [CompletionResult]::new('check', 'check', [CompletionResultType]::ParameterValue, 'Check one peer''s current copy of our latest local revision')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'bbcli;peer;help;connect' {
            break
        }
        'bbcli;peer;help;pin' {
            break
        }
        'bbcli;peer;help;unpin' {
            break
        }
        'bbcli;peer;help;list' {
            break
        }
        'bbcli;peer;help;check' {
            break
        }
        'bbcli;peer;help;help' {
            break
        }
        'bbcli;file' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'Print the names of all files in the latest encrypted content blob')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Add or replace a file in the latest encrypted content blob')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Download a file from the latest encrypted content blob')
            [CompletionResult]::new('delete', 'delete', [CompletionResultType]::ParameterValue, 'Delete a file from the latest encrypted content blob')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'bbcli;file;list' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;file;set' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;file;get' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;file;delete' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;file;help' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'Print the names of all files in the latest encrypted content blob')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Add or replace a file in the latest encrypted content blob')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Download a file from the latest encrypted content blob')
            [CompletionResult]::new('delete', 'delete', [CompletionResultType]::ParameterValue, 'Delete a file from the latest encrypted content blob')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'bbcli;file;help;list' {
            break
        }
        'bbcli;file;help;set' {
            break
        }
        'bbcli;file;help;get' {
            break
        }
        'bbcli;file;help;delete' {
            break
        }
        'bbcli;file;help;help' {
            break
        }
        'bbcli;config' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Print the current configuration and derived storage usage data')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update one or more configuration fields')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'bbcli;config;get' {
            [CompletionResult]::new('--peers-storage', '--peers-storage', [CompletionResultType]::ParameterName, 'peers_storage prints only the peer-storage budget field')
            [CompletionResult]::new('--min-replicas', '--min-replicas', [CompletionResultType]::ParameterName, 'min_replicas prints only the minimum replica target field')
            [CompletionResult]::new('--resource-policy', '--resource-policy', [CompletionResultType]::ParameterName, 'resource_policy prints only the current read-only peer runtime limits')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;config;set' {
            [CompletionResult]::new('--peers-storage', '--peers-storage', [CompletionResultType]::ParameterName, 'peers_storage sets the total bytes allocated to peer storage')
            [CompletionResult]::new('--min-replicas', '--min-replicas', [CompletionResultType]::ParameterName, 'min_replicas sets the minimum replica target for our content')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'bbcli;config;help' {
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Print the current configuration and derived storage usage data')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update one or more configuration fields')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'bbcli;config;help;get' {
            break
        }
        'bbcli;config;help;set' {
            break
        }
        'bbcli;config;help;help' {
            break
        }
        'bbcli;help' {
            [CompletionResult]::new('state', 'state', [CompletionResultType]::ParameterValue, 'Print daemon state')
            [CompletionResult]::new('init', 'init', [CompletionResultType]::ParameterValue, 'Initialize daemon storage with the main password or complete one recovery-mode initialization')
            [CompletionResult]::new('unlock', 'unlock', [CompletionResultType]::ParameterValue, 'Send the main password to the daemon unlock path')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Ask the daemon to shut down gracefully')
            [CompletionResult]::new('peer', 'peer', [CompletionResultType]::ParameterValue, 'Manage known peers')
            [CompletionResult]::new('file', 'file', [CompletionResultType]::ParameterValue, 'Manage files in the latest encrypted content blob')
            [CompletionResult]::new('config', 'config', [CompletionResultType]::ParameterValue, 'Read or update daemon configuration')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'bbcli;help;state' {
            break
        }
        'bbcli;help;init' {
            [CompletionResult]::new('complete', 'complete', [CompletionResultType]::ParameterValue, 'Complete recovery-mode initialization and allow publication')
            break
        }
        'bbcli;help;init;complete' {
            break
        }
        'bbcli;help;unlock' {
            break
        }
        'bbcli;help;stop' {
            break
        }
        'bbcli;help;peer' {
            [CompletionResult]::new('connect', 'connect', [CompletionResultType]::ParameterValue, 'Add a peer onion identifier to the daemon''s known peer list')
            [CompletionResult]::new('pin', 'pin', [CompletionResultType]::ParameterValue, 'Pin a tracked peer so local policy treats it as operator-protected')
            [CompletionResult]::new('unpin', 'unpin', [CompletionResultType]::ParameterValue, 'Remove an existing operator pin from a tracked peer')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'Print the daemon''s current peer inventory')
            [CompletionResult]::new('check', 'check', [CompletionResultType]::ParameterValue, 'Check one peer''s current copy of our latest local revision')
            break
        }
        'bbcli;help;peer;connect' {
            break
        }
        'bbcli;help;peer;pin' {
            break
        }
        'bbcli;help;peer;unpin' {
            break
        }
        'bbcli;help;peer;list' {
            break
        }
        'bbcli;help;peer;check' {
            break
        }
        'bbcli;help;file' {
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'Print the names of all files in the latest encrypted content blob')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Add or replace a file in the latest encrypted content blob')
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Download a file from the latest encrypted content blob')
            [CompletionResult]::new('delete', 'delete', [CompletionResultType]::ParameterValue, 'Delete a file from the latest encrypted content blob')
            break
        }
        'bbcli;help;file;list' {
            break
        }
        'bbcli;help;file;set' {
            break
        }
        'bbcli;help;file;get' {
            break
        }
        'bbcli;help;file;delete' {
            break
        }
        'bbcli;help;config' {
            [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Print the current configuration and derived storage usage data')
            [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Update one or more configuration fields')
            break
        }
        'bbcli;help;config;get' {
            break
        }
        'bbcli;help;config;set' {
            break
        }
        'bbcli;help;help' {
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
