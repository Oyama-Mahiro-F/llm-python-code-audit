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
