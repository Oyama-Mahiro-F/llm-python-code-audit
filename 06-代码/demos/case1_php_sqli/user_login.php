<?php
// ============================================================================
// 演示案例 1:PHP SQL 注入(CWE-89)
// 对应真实漏洞:CVE-2019-15573 — Gesior-AAC tankyou.php SQL 注入(CVSS 9.8)
//   NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-15573
// 漏洞模式:用户可控输入经字符串拼接进入 SQL 语句,未做参数化/转义
// 说明:被测函数第一个形参接收外部输入(真实代码中来自 $_GET['user']),
//       便于 harness 注入 payload;$conn 在真实代码中由连接池注入。
// ============================================================================

function login_check($user)
{
    $conn = null;   // 真实代码由连接池注入,演示中置空
    $sql = "SELECT id, name FROM users WHERE name = '" . $user . "'";
    $res = mysqli_query($conn, $sql);
    return $res;
}
