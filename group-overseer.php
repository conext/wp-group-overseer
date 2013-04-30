<?php


/* Permission/role mapping */
$role_map = array(
    'admin' => 'administrator',
    'manager' => 'editor',
    'memeber' => 'contributor',
);

function sync_group_resources($login) {
    global $role_map;

    $user = get_user_by('login', $login);
    $uid_urn = get_user_meta($user->ID, 'aim', true);

    $groups = _grab_groups($uid_urn);
    error_log(var_export($groups, true));
    foreach ($groups as &$group) {
        $group['resources'] = _interrogate_regroup($group['id']);
    }
    unset($group);


    /* Massive hackage. No class, no elegance. Cheap code. */
    error_log("Done inserting resources into description.");
    error_log(var_export($groups, true));
    foreach ($groups as $group) {
        $team_role = $group['voot_membership_role']; 
        
        foreach ($group['resources'] as $res) {
            $res = $res['resource'];
            $domain = $res['local_name'] . '.wordpress.identitylabs.org';
            /* Create new blog. */
            error_log("Creating new blog: uri = {$domain}.");
            $ret = create_empty_blog($domain, '/', $res['local_name']);
            error_log("create_empty_blog retval = {$ret}");

            /* Add current user to blog with right role */
            $bid = get_blog_id_from_url($domain); 
            $uid = $user->ID; 
            error_log("blog id = " . $bid);
            error_log("user id = " . $uid);
            error_log("role will be = " . $role_map[$team_role]);

            $ret = add_user_to_blog($bid, $uid, $role_map[$team_role]); 
            error_log("retval: " . var_export($ret, true));
        }
    }
}

function _grab_groups($uid) {
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
        "https://api.jacson.jiscadvance.biz/v1/social/rest/groups/{$uid}",
        'alamakota',
        'alamakota',
        $body
    );

    /* Finalize request, decode and return. */
    $uri = "https://api.jacson.jiscadvance.biz/v1/social/rest/groups/{$uid}"; 
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

function _interrogate_regroup($gid) {
    $req = new WP_Http;
    $username = 'wordpress';
    $password = 'letterpull';
    $headers = array('Authorization' => 'Basic ' . base64_encode("$username:$password"));
    $api_uri = "https://regroup.identitylabs.org/group/{$gid}/resources";
    $result = $req->request($api_uri, array('headers' => $headers, 'sslverify' => false));
    error_log('SWOOSH');
    error_log(var_export($result['body'], true));
    return json_decode($result['body'], true);
}

add_action('wp_login', 'sync_group_resources', 1000);
