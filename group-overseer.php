<?php

/* Include scheme, don't include trailing slash. */
/* MUST be HTTPS! */
define('REGROUP_URL', 'https://regroup.collaborate.jiscadvance.biz');;
define('TEAMS_API', 'https://api.collaborate.jiscadvance.biz');
define('MAIN_SITE_URL', 'https://wordpress.apps.jiscconext.org.uk');
/* Include leading dot: .blog.example.com */
define('WORDPRESS_DOMAIN', '.wordpress.apps.jiscconext.org.uk');

/* Regroup related configuration. */
define('REGROUP_USERNAME', 'wordpress');
define('REGROUP_PASSWORD', 'letterpull');

/* Permission/role mapping */
$role_map = array(
    'admin' => 'administrator',
    'manager' => 'editor',
    'member' => 'contributor',
);

/* Wrapper around var_export(..., true) */
function _ve($x) {
    return var_export($x, true);
}

add_action('wp_login', 'sync_group_resources', 1000);
function sync_group_resources($login) {
    global $role_map;

    $user = get_user_by('login', $login);
    $uid_urn = get_user_meta($user->ID, 'conext_uid', true);
    error_log("Full UID pulled from meta: " . $uid_urn);    

    $groups = _grab_groups($uid_urn);
    error_log("Groups:");
    error_log(_ve($groups));
    foreach ($groups as &$group) {
        $group['resources'] = _interrogate_regroup($group['id']);
    }
    unset($group);


    /* Massive hackage. No class, no elegance. Cheap code. */
    error_log("Done inserting resources into description.");
    error_log(_ve($groups));
    foreach ($groups as $group) {
        $team_role = $group['voot_membership_role']; 
        
        foreach ($group['resources'] as $res) {
            $res = $res['resource'];
            $domain = $res['local_name'] . WORDPRESS_DOMAIN;
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
            error_log("retval: " . _ve($ret));

            /* Add user to main site blog with lowest privilege. */
            error_log("Adding user to main site as a subscriber..");
            $ret = add_user_to_blog(1, $uid, 'subscriber');
            error_log("retval: " . _ve($ret));

            error_log("Setting blog title..");
            if(!get_blog_option($bid, 'blogname')) {
                switch_to_blog($bid);
                $ret = update_option('blogname', "The {$res['local_name']} blog");
                error_log("update_option('blogname', ...) ret: " . _ve($ret));
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
        TEAMS_API . "/v1/social/rest/groups/{$uid}",
        'alamakota',
        'alamakota',
        $body
    );

    /* Finalize request, decode and return. */
    $uri = TEAMS_API . "/v1/social/rest/groups/{$uid}"; 
	error_log("request dest: " . $uri);
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
    $username = REGROUP_USERNAME;
    $password = REGROUP_PASSWORD;
    $headers = array('Authorization' => 'Basic ' . base64_encode("$username:$password"));
    $api_uri = REGROUP_URL . "/group/{$gid}/resources";
    error_log($api_uri);
    $result = $req->request($api_uri, array('headers' => $headers, 'sslverify' => false));
    error_log('SWOOSH');
    error_log(_ve($result['body']));
    error_log(_ve($result));
    return json_decode($result['body'], true);
}

add_action('init', 'log_in_unless_xhr', 2000);
function log_in_unless_xhr() {
    /* Force login via MAIN_SITE_URL (because SAML) UNLESS request is XHR. */
    if (!is_user_logged_in() && !isset($_SERVER['HTTP_ORIGIN']) && get_site_url() !== MAIN_SITE_URL) {
	/* 
         * The user is NOT logged in, didn't request the main site, and it's not an XHR request.
         * Action: we force the user to log in by redirecting to /wp-login.php, which initiates the
         * SAML login flow (this is because of the simplesamlphp-authentication plugin
         * which basically hijacks that page.
         */ 
        error_log("Not logged in and no Origin: header.");
        /* why? because wp-login.php?redirect_to doesn't work with the SAML plugin. */
        setcookie('xx_redirect_to', get_site_url(), 0, '', WORDPRESS_DOMAIN);
        wp_redirect(MAIN_SITE_URL . '/wp-login.php');
        exit;
    } else if (is_user_logged_in() && isset($_COOKIE['xx_redirect_to']) && get_site_url() == MAIN_SITE_URL) {
	/* 
	 * User is logged in, hit the main site (possibly after just logging in)
    	 * and has an xx_redirect_t cookie set. We interrupt the normal course of events
	 * and redirect him to wherever the cookie is pointing to.
         */
        $target = $_COOKIE['xx_redirect_to'];
        setcookie('xx_redirect_to', '-', 1, '', WORDPRESS_DOMAIN);
        wp_redirect($target);
        exit;
    } else if (is_user_logged_in() && isset($_COOKIE['xx_redirect_to']) && get_site_url() !== MAIN_SITE_URL) {
	/*
	 * The user is logged in, a redirect cookie is set, but the site requested is not the main site.
         * What does this mean? That the user got here by hitting the if(){} above.
	 * All's good, we clear the cookie to have a clean slate.
         */
        setcookie('xx_redirect_to', '-', 1, '', WORDPRESS_DOMAIN);
    }
}

add_action('init', 'after_provisioning_redirect', 1000);
function after_provisioning_redirect() {
    /* Only pertains to main site. */
    // TODO: see if get_site_url is available when doing add_action instead
    if (!get_site_url() == MAIN_SITE_URL) {
        if (isset($_COOKIE['conext_redirect'])) {
            setcookie('conext_redirect', '', 1, '', WORDPRESS_DOMAIN);
        }
        error_log("Not main site, skipping.");
        return;
    }

    if (isset($_REQUEST['conext_redirect']) && is_user_logged_in()) {
        error_log("new_site in request, user logged in.");
        sync_group_resources($GLOBALS['userdata']->user_login); 
        // TODO: unsafe?
        wp_redirect('https://' . $_REQUEST['conext_redirect'] . WORDPRESS_DOMAIN);
        exit;
    } else if (isset($_REQUEST['conext_redirect']) && !is_user_logged_in()) {
        error_log("new site in request, user not logged in - setting cookie");
        setcookie('conext_redirect', $_REQUEST['conext_redirect'], 0, '', WORDPRESS_DOMAIN);
        wp_redirect(get_site_url() . '/wp-login.php');
        exit;
    } else if (isset($_COOKIE['conext_redirect']) && ($_COOKIE['conext_redirect']) && is_user_logged_in()) {
        error_log("cookie set, user logged in...");
        // Assuming resources were synced & the user just logged in.
        $target = $_COOKIE['conext_redirect'];
        setcookie('conext_redirect', '', 1, '', WORDPRESS_DOMAIN);
        wp_redirect('https://' . $target . WORDPRESS_DOMAIN);
        exit;
    }   
}

add_action('wp_logout', 'logout_redirect', 1);
function logout_redirect() {
    error_log('wp_logout');
    wp_clear_auth_cookie();
    wp_redirect(MAIN_SITE_URL); 
    exit;
}

add_action('clear_auth_cookie', 'clear_custom_cookies', 1);
function clear_custom_cookies() {
    setcookie('PHPSESSID', ' ', time() - 31536000, '', WORDPRESS_DOMAIN);
    setcookie('SimpleSAMLAuthToken', ' ', time() - 31536000, '', WORDPRESS_DOMAIN);
    setcookie('xx_redirect_to', ' ', time() - 31536000, '', WORDPRESS_DOMAIN);
    setcookie('conext_redirect', ' ', time() - 31536000, '', WORDPRESS_DOMAIN);
}
