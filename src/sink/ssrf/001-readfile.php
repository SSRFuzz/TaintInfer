<?php


function readfile($filename, ...$args) {
    taintinfer_check_ssrf($filename, taintinfer_translate("Server Side Request Forgery"));
    return call_user_func(TAINTINFER_RENAME_PREFIX."readfile", $filename, ...$args);
}
