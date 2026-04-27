
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'bbd' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'bbd'
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
        'bbd' {
            [CompletionResult]::new('--local-addr', '--local-addr', [CompletionResultType]::ParameterName, 'local_addr is the local loopback address for the CLI gRPC service')
            [CompletionResult]::new('--data-dir', '--data-dir', [CompletionResultType]::ParameterName, 'data_dir is the base directory for all daemon state')
            [CompletionResult]::new('--arti-config', '--arti-config', [CompletionResultType]::ParameterName, 'arti_config is one optional Arti TOML file for custom test networks')
            [CompletionResult]::new('--test-clock', '--test-clock', [CompletionResultType]::ParameterName, 'test_clock enables the hidden daemon test clock control RPCs')
            [CompletionResult]::new('--disable-maintenance', '--disable-maintenance', [CompletionResultType]::ParameterName, 'disable_maintenance disables the background maintenance loop for tests')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
