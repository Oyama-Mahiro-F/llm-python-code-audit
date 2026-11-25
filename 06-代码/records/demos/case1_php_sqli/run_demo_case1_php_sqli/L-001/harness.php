<?php
// 由 auditor.harness 自动生成(alert_id=L-001);勿手工编辑。
// === 1. mock 桩(mock_gen.py 产出;接缝重定向的接收方)==================
// --- mock 桩(模板生成,记录 mysqli_query 的 SQL 参数,不执行任何 SQL)---
$GLOBALS['CAPTURED'] = ['sink_api' => 'mysqli_query', 'calls' => []];

class __MockResult
{
    public $num_rows = 0;
    public function fetch_assoc() { return null; }
    public function fetch_row() { return null; }
    public function fetch_array() { return null; }
}

function __mock_mysqli_query($link, $query)
{
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($query) ? $query : var_export($query, true),
    ];
    return new __MockResult();
}


// === 2. 业务源码片段(extract.py 产出;sink 调用已重定向)===============
function login_check($user)
{
    $conn = null;   // 真实代码由连接池注入,演示中置空
    $sql = "SELECT id, name FROM users WHERE name = '" . $user . "'";
    $res = __mock_mysqli_query($conn, $sql);
    return $res;
}


// === 3. 送入 payload,触发 sink =========================================
$payload = 'zxq-demo-marker\' OR \'1\'=\'1';
$result = ['captured' => null, 'payload' => $payload, 'error' => null];
try {
    $fn = 'login_check';
    $fn($payload);
} catch (\Throwable $e) {
    $result['error'] = get_class($e) . ': ' . $e->getMessage();
}
$result['captured'] = isset($GLOBALS['CAPTURED']) ? $GLOBALS['CAPTURED'] : null;
echo "@@RESULT@@" . json_encode(
    $result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
) . PHP_EOL;
