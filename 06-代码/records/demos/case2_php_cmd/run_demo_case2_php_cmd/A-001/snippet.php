function ping_host($host)
{
    $cmd = "ping -c 1 " . $host;
    $output = shell_exec($cmd);
    return $output;
}
