<?php

function sync_group_resources() {
    $groups = _grab_groups();
    error_log(var_export($groups, true));
    $resources = _interrogate_regroup();
    error_log(var_export($resources, true));
}

function _grab_groups() {
    /* Stitch together the request and send it. */
    $req = new WP_Http;
    $body = array(
        'oauth_version' => '1.0',
        'oauth_timestamp' => time(), 
        'oauth_signature_method' => 'HMAC-SHA1',
        'oauth_nonce' => md5(microtime().mt_rand()), 
        'oauth_consumer_key' => 'alamakota',
    );

    /* Slide in that OAuth signature. */
    $body['oauth_signature'] = _get_sig(
        'https://api.jacson.jiscadvance.biz/v1/social/rest/groups/urn:collab:person:example.com:admin',
        'alamakota',
        'alamakota',
        $body
    );

    /* Finalize request, decode and return. */
    $uri = 'https://api.jacson.jiscadvance.biz/v1/social/rest/groups/urn:collab:person:example.com:admin'; 
    $uri .= '?' . http_build_query($body);
    $res = $req->request($uri, array('sslverify'=>false));
    $re_json = json_decode($res['body'], true);
    return $re_json['entry'];
}

function _get_sig($uri, $c_key, $c_secret, $params) {
 
    $method = 'GET';
    $raw_params = $params;
    $enc_params = array();
 
    /* percent encode parameters and values */
    foreach ($raw_params as $k => $v) {
        $enc_params[urlencode($k)] = urlencode($v);
    }
 
    /* sort alphabetically */
    ksort($enc_params);
 
    /* join them as required, with = and & */
    $param_string = '';
    foreach ($enc_params as $k => $v) {
        $param_string .= $k;
        $param_string .= '=';
        $param_string .= $v;
        $param_string .= '&';
    }
 
    /* fix trailing ampersand */
    $param_string = rtrim($param_string, '&');
 
    /* build final base string */
    $base_string = '';
    $base_string .= strtoupper($method);
    $base_string .= '&';
    $base_string .= urlencode($uri);
    $base_string .= '&';
    $base_string .= urlencode($param_string);
    
    /* build key, we're not using a token secret in our case */
    $key = urlencode($c_secret) . '&';
 
    /* passing true to hash_hmac makes it return binary data */
    return base64_encode(hash_hmac('sha1', $base_string, $key, true));
}

function _interrogate_regroup() {
    $req = new WP_Http;
    $username = 'photo_hut';
    $password = 'photo_hut';
    $headers = array('Authorization' => 'Basic ' .  base64_encode("$username:$password"));
    $api_uri = 'https://regroup.identitylabs.org/group/1000/resources';
    $result = $req->request($api_uri, array('headers' => $headers, 'sslverify' => false));
    error_log('SWOOSH');
    error_log(var_export($result, true));
}

add_action('wp_login', 'sync_group_resources');
