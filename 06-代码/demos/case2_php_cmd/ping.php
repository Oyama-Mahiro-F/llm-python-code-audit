<?php
// ============================================================================
// 演示案例 2:PHP 命令注入(CWE-78)
// 对应真实漏洞:CVE-2019-9194 — elFinder < 2.1.48 PHP connector 命令注入
//   NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-9194
//   同模式参照:CVE-2019-10774 — php-shellcommand < 1.6.1 命令注入
// 漏洞模式:外部输入拼进 shell 命令串,未过滤 shell 元字符(; | && 等)
// 说明:第一个形参接收外部输入(真实代码中来自 $_POST['host'])。
// ============================================================================

function ping_host($host)
{
    $cmd = "ping -c 1 " . $host;
    $output = shell_exec($cmd);
    return $output;
}
