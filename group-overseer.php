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
    error_log("Groups:");
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

            error_log("Setting blog title..");
            if(!get_blog_option($bid, 'blogname')) {
                switch_to_blog($bid);
                $ret = update_option('blogname', "The {$res['local_name']} blog");
                error_log("update_option ret: " . var_export($ret, true));
                restore_current_blog();
            }
        }
    }
}

function _grab_groups($uid) {
    error_log("Asking for {$uid} resources.");
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
    error_log("API response body: ");
    error_log($res['body']);
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

function check_if_sync_forced() {
    /* Here be dragons and the occasional kung-fu savvy panda. */ 

    /// Override the whole thing (move out later)
    if (get_site_url() == 'https://wordpress.identitylabs.org') {
        error_log("doing the check");    
        if (is_user_logged_in()) {
            if (isset($_COOKIE['conext_login_redirect'])) {
                error_log("I though I saw a pussy-cat!");
                error_log($_COOKIE['conext_login_redirect']);
                wp_redirect($_COOKIE['conext_login_redirect']);
                exit;
            }
        } else {
            return;
        }
    } else {
        if (isset($_COOKIE['conext_login_redirect'])) {
            error_log("Clearing redirect cookie.");
            setcookie('conext_login_redirect', 'the ghosts that haunt us..', 1, '', '.wordpress.identitylabs.org');
        }
    }

    error_log("is_user_logged_in(): " . var_export(is_user_logged_in(), true));
    error_log("check_if_sync_forced");
    if (isset($_REQUEST['force_resource_sync']) && is_user_logged_in()) {
        error_log("Resource sync forced: synchronizing.");
        sync_group_resources($GLOBALS['userdata']->user_login);
    } else if (isset($_REQUEST['force_resource_sync']) && !is_user_logged_in()){
        error_log("Convenient. Resource sync forced, but user is not logged in. Will log in.");
        /* save URI */
        setcookie('conext_login_redirect', get_site_url(), 0, '', '.wordpress.identitylabs.org');
        wp_redirect('https://wordpress.identitylabs.org/wp-login.php');
        exit; 
    }  
}

function after_provisioning_redirect() {
    /* Only pertains to main site. */
    // TODO: see if get_site_url is available when doing add_action instead
    if (!get_site_url() == "https://wordpress.identitylabs.org") {
        if (isset($_COOKIE['conext_redirect'])) {
            setcookie('conext_redirect', '', 1, '', '.wordpress.identitylabs.org');
        }
        error_log("Not main site, skipping.");
        return;
    }

    if (isset($_REQUEST['conext_redirect']) && is_user_logged_in()) {
        error_log("new_site in request, user logged in.");
        sync_group_resources($GLOBALS['userdata']->user_login); 
        // TODO: unsafe?
        wp_redirect('https://' . $_REQUEST['conext_redirect'] . '.wordpress.identitylabs.org');
        exit;
    } else if (isset($_REQUEST['conext_redirect']) && !is_user_logged_in()) {
        error_log("new site in request, user not logged in - setting cookie");
        setcookie('conext_redirect', $_REQUEST['conext_redirect'], 0, '', '.wordpress.identitylabs.org');
        wp_redirect(get_site_url() . '/wp-login.php');
        exit;
    } else if (isset($_COOKIE['conext_redirect']) && ($_COOKIE['conext_redirect']) && is_user_logged_in()) {
        error_log("cookie set, user logged in...");
        // Assuming resources were synced & the user just logged in.
        $target = $_COOKIE['conext_redirect'];
        setcookie('conext_redirect', '', 1, '', 'wordpress.identitylabs.org');
        wp_redirect('https://' . $target . '.wordpress.identitylabs.org');
        exit;
    }   
}

function add_page_to_dashboard() {
    add_menu_page("Overseer", "Overseer", "manage_networks", "overseer_insight", "");
}

add_action('wp_login', 'sync_group_resources', 1000);
//add_action('init', 'check_if_sync_forced', 1000);
add_action('init', 'after_provisioning_redirect', 1000);
add_action('admin_menu', 'add_page_to_dashboard', 1000);
