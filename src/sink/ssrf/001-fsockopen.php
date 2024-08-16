<?php

function fsockopen($hostname, $port=-1, &$errno=NULL, &$errstr=NULL, $timeout=NULL) {
    // reference params
    $timeout = ini_get("default_socket_timeout");
    taintinfer_check_ssrf($hostname, taintinfer_translate("Server Side Request Forgery"));
    return call_user_func_array(TAINTINFER_RENAME_PREFIX."fsockopen", array($hostname, $port, &$errno, &$errstr, $timeout));
}