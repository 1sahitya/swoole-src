<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);
$client->set(array(
    'open_length_check'     => 1,
    'package_length_type'   => 'N',
    'package_length_offset' => 0,       //第N个字节是包长度的值
    'package_body_offset'   => 4,       //第几个字节开始计算长度
    'package_max_length'    => 2000000,  //协议最大长度
));

if(!$client->connect('127.0.0.1', 9501))
{
    exit("connect failed\n");
}

for ($i = 0; $i < 10; $i++)
{
    $data = array(
        'str1' => str_repeat('A', rand(1000, 9000)),
        'str2' => str_repeat('B', rand(1000, 9000)),
        'str3' => str_repeat('C', rand(1000, 9000)),
    );

    $data['int1'] = rand(100000, 999999);

    $sendStr = serialize($data);
    $sendData = pack('N', strlen($sendStr)) . $sendStr;
    $client->send($sendData);
    $resp = $client->recv();
    echo "send length=" . strlen($sendData) . ", SerId={$data['int1']}\n";

    $data2 = unserialize(substr($resp, 4));
    echo "recv length=" . strlen($resp) . ", SerId={$data2['int1']}\n";
}
sleep(2);

