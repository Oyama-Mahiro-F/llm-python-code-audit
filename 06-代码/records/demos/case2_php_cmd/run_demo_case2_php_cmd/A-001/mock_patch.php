// --- mock 桩(模板生成,记录 shell 命令串,不执行任何命令)---
$GLOBALS['CAPTURED'] = ['sink_api' => 'shell_exec', 'calls' => []];

function __mock_shell_exec($cmd)
{
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($cmd) ? $cmd : var_export($cmd, true),
    ];
    return '';
}

function __mock_exec($cmd, &$output = null, &$code = null)
{
    $output = [];
    $code = 0;
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($cmd) ? $cmd : var_export($cmd, true),
    ];
    return '';
}

function __mock_system($cmd, &$code = null)
{
    $code = 0;
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($cmd) ? $cmd : var_export($cmd, true),
    ];
    return '';
}

function __mock_passthru($cmd, &$code = null)
{
    $code = 0;
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($cmd) ? $cmd : var_export($cmd, true),
    ];
    return '';
}
