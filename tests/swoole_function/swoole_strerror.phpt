--TEST--
swoole_function: swoole_strerror
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
if (!is_alpine_linux()) {
    assert(
        swoole_strerror(IS_MAC_OS ? 4 : -4 /*EAI_FAIL*/, SWOOLE_STRERROR_GAI) ===
        'Non-recoverable failure in name resolution'
    );
    assert(
        swoole_strerror(2 /*NO_ADDRESS*/, SWOOLE_STRERROR_DNS) ===
        'Host name lookup failure'
    );
}
echo swoole_strerror(SOCKET_ECONNRESET) . "\n";
echo swoole_strerror(SWOOLE_ERROR_FILE_NOT_EXIST) . "\n";
if (!is_alpine_linux()) {
    $unknown = swoole_strerror(SWOOLE_ERROR_MALLOC_FAIL - 1);
    $sw_unknown = swoole_strerror(SWOOLE_ERROR_MALLOC_FAIL - 1, SWOOLE_STRERROR_SWOOLE);
    assert($unknown === $sw_unknown);
} else {
    assert(swoole_strerror(SWOOLE_ERROR_MALLOC_FAIL - 1) === 'No error information');
}
?>
--EXPECT--
Connection reset by peer
File not exist