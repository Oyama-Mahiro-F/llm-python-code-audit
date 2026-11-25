<?php
// 由 auditor.harness 自动生成(alert_id=A-001);勿手工编辑。
// === 1. mock 桩(mock_gen.py 产出;接缝重定向的接收方)==================
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


// === 2. 业务源码片段(extract.py 产出;sink 调用已重定向)===============
function ping_host($host)
{
    $cmd = "ping -c 1 " . $host;
    $output = __mock_shell_exec($cmd);
    return $output;
}


// === 3. 送入 payload,触发 sink =========================================
$payload = '127.0.0.1; echo zxq-demo-marker';
$result = ['captured' => null, 'payload' => $payload, 'error' => null];
try {
    $fn = 'ping_host';
    $fn($payload);
} catch (\Throwable $e) {
    $result['error'] = get_class($e) . ': ' . $e->getMessage();
}
$result['captured'] = isset($GLOBALS['CAPTURED']) ? $GLOBALS['CAPTURED'] : null;
echo "@@RESULT@@" . json_encode(
    $result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
) . PHP_EOL;
