function login_check($user)
{
    $conn = null;   // 真实代码由连接池注入,演示中置空
    $sql = "SELECT id, name FROM users WHERE name = '" . $user . "'";
    $res = mysqli_query($conn, $sql);
    return $res;
}
