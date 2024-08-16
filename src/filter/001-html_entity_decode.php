<?php


function html_entity_decode($string, ...$args) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."html_entity_decode", $string, ...$args);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($string)) {
        taintinfer_zmark($result);
    }

    return $result;
}
