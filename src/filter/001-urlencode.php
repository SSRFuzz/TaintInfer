<?php


function urlencode($str) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."urlencode", $str);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($str)) {
        taintinfer_zmark($result);
    }

    return $result;
}
