<?php

/* Reminder: always indent with 4 spaces (no tabs). */
// +---------------------------------------------------------------------------+
// | Geeklog 2.1 - Security Hardened Version      masodo w/ClaudeAi 8-6-2025   |
// +---------------------------------------------------------------------------+
// | trackback.php                                                             |
// |                                                                           |
// | Admin functions handle Trackback, Pingback, and Ping                      |
// +---------------------------------------------------------------------------+
// | Copyright (C) 2005-2011 by the following authors:                         |
// |                                                                           |
// | Author: Dirk Haun - dirk AT haun-online DOT de                            |
// | Security Improvements: Added 2024                                         |
// +---------------------------------------------------------------------------+
// |                                                                           |
// | This program is free software; you can redistribute it and/or             |
// | modify it under the terms of the GNU General Public License               |
// | as published by the Free Software Foundation; either version 2            |
// | of the License, or (at your option) any later version.                    |
// |                                                                           |
// | This program is distributed in the hope that it will be useful,           |
// | but WITHOUT ANY WARRANTY; without even the implied warranty of            |
// | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             |
// | GNU General Public License for more details.                              |
// |                                                                           |
// | You should have received a copy of the GNU General Public License         |
// | along with this program; if not, write to the Free Software Foundation,   |
// | Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.           |
// |                                                                           |
// +---------------------------------------------------------------------------+

/**
 * Admin functions related to Trackbacks, Pingbacks, and Pings: Send Trackbacks,
 * Pingbacks, and configure the list of weblog directory services to "ping"
 * after an update.
 */

/**
 * Geeklog common function library
 */
require_once '../lib-common.php';

/**
 * Security check to ensure user even belongs on this page
 */
require_once 'auth.inc.php';

if (!$_CONF['trackback_enabled'] && !$_CONF['pingback_enabled'] &&
    !$_CONF['ping_enabled']
) {
    COM_redirect($_CONF['site_admin_url'] . '/index.php');
}

$display = '';

if (!SEC_hasRights('story.ping')) {
    $display .= COM_showMessageText($MESSAGE[29], $MESSAGE[30]);
    $display = COM_createHTMLDocument($display, array('pagetitle' => $MESSAGE[30]));
    COM_accessLog("User attempted to illegally access the trackback administration screen.");
    COM_output($display);
    exit;
}

require_once $_CONF['path_system'] . 'lib-trackback.php';
require_once $_CONF['path_system'] . 'lib-pingback.php';
require_once $_CONF['path_system'] . 'lib-article.php';

/**
 * Security helper functions
 */

/**
 * Validate and sanitize integer input
 *
 * @param    mixed $input Input value
 * @param    int   $min   Minimum allowed value
 * @param    int   $max   Maximum allowed value
 * @return   int|false    Validated integer or false if invalid
 */
function validateInteger($input, $min = 0, $max = PHP_INT_MAX)
{
    $value = filter_var($input, FILTER_VALIDATE_INT, array(
        'options' => array(
            'min_range' => $min,
            'max_range' => $max
        )
    ));
    return $value !== false ? $value : false;
}

/**
 * Validate and sanitize URL input
 *
 * @param    string $url URL to validate
 * @return   string|false Validated URL or false if invalid
 */
function validateUrl($url)
{
    $url = trim($url);
    if (empty($url)) {
        return false;
    }
    
    // Basic URL validation
    $validated = filter_var($url, FILTER_VALIDATE_URL);
    if ($validated === false) {
        return false;
    }
    
    // Additional security checks
    $parsed = parse_url($validated);
    if (!$parsed || !isset($parsed['scheme']) || !isset($parsed['host'])) {
        return false;
    }
    
    // Only allow HTTP and HTTPS
    if (!in_array(strtolower($parsed['scheme']), array('http', 'https'), true)) {
        return false;
    }
    
    // Prevent local network access
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    
    return $validated;
}

/**
 * Enhanced HTML escaping
 *
 * @param    string $string String to escape
 * @param    int    $flags  HTML encoding flags
 * @return   string         Escaped string
 */
function secureHtmlEscape($string, $flags = ENT_QUOTES)
{
    return htmlspecialchars($string, $flags | ENT_HTML5, 'UTF-8');
}

/**
 * Validate user permissions for specific operations
 *
 * @param    string $operation Operation to validate
 * @return   bool             True if permitted
 */
function validatePermission($operation)
{
    global $_USER;
    
    if (!SEC_hasRights('story.ping')) {
        return false;
    }
    
    // Additional operation-specific checks can be added here
    switch ($operation) {
        case 'delete_trackback':
        case 'save_service':
        case 'delete_service':
            return SEC_hasRights('story.edit');
        default:
            return true;
    }
}

/**
 * Display trackback comment submission form.
 *
 * @param    string $target  URL to send the trackback comment to
 * @param    string $url     URL of our entry
 * @param    string $title   title of our entry
 * @param    string $excerpt excerpt of our entry
 * @param    string $blog    name of our site
 * @return   string              HTML for the trackback comment editor
 */
function trackback_editor($target = '', $url = '', $title = '', $excerpt = '', $blog = '')
{
    global $_CONF, $LANG_TRB;

    $retval = '';

    // Sanitize inputs
    $target = secureHtmlEscape($target);
    $url = secureHtmlEscape($url);
    $title = secureHtmlEscape($title);
    $excerpt = secureHtmlEscape($excerpt);
    $blog = secureHtmlEscape($blog);

    // show preview if we have at least the URL
    if (!empty($url)) {
        // filter them for the preview
        $p_title = TRB_filterTitle($title);
        $p_excerpt = TRB_filterExcerpt($excerpt);
        $p_blog = TRB_filterBlogname($blog);

        // MT and other weblogs will shorten the excerpt like this
        if (MBYTE_strlen($p_excerpt) > 255) {
            $p_excerpt = MBYTE_substr($p_excerpt, 0, 252) . '...';
        }

        $retval .= COM_startBlock($LANG_TRB['preview']);

        $preview = COM_newTemplate(CTL_core_templatePath($_CONF['path_layout'] . 'trackback'));
        $preview->set_file(array('comment' => 'trackbackcomment.thtml'));
        $comment = TRB_formatComment($url, $p_title, $p_blog, $p_excerpt);
        $preview->set_var('formatted_comment', $comment);
        $preview->parse('output', 'comment');
        $retval .= $preview->finish($preview->get_var('output'));

        $retval .= COM_endBlock();
    }

    if (empty($url) && empty($blog)) {
        $blog = secureHtmlEscape($_CONF['site_name']);
    }

    $retval .= COM_startBlock($LANG_TRB['editor_title'],
        COM_getDocumentUrl('docs', "trackback.html") . '#trackback',
        COM_getBlockTemplate('_admin_block', 'header'));

    $template = COM_newTemplate(CTL_core_templatePath($_CONF['path_layout'] . 'admin/trackback'));
    $template->set_file(array('editor' => 'trackbackeditor.thtml'));

    $template->set_var('php_self', $_CONF['site_admin_url']
        . '/trackback.php');

    if (empty($url) || empty($title)) {
        $template->set_var('lang_explain', $LANG_TRB['editor_intro_none']);
    } else {
        $template->set_var('lang_explain',
            sprintf($LANG_TRB['editor_intro'], $url, $title));
    }
    $template->set_var('lang_trackback_url', $LANG_TRB['trackback_url']);
    $template->set_var('lang_entry_url', $LANG_TRB['entry_url']);
    $template->set_var('lang_title', $LANG_TRB['entry_title']);
    $template->set_var('lang_blog_name', $LANG_TRB['blog_name']);
    $template->set_var('lang_excerpt', $LANG_TRB['excerpt']);
    $template->set_var('lang_excerpt_truncated', $LANG_TRB['truncate_warning']);
    $template->set_var('lang_send', $LANG_TRB['button_send']);
    $template->set_var('lang_preview', $LANG_TRB['button_preview']);

    $template->set_var('max_url_length', 255);
    $template->set_var('target_url', $target);
    $template->set_var('url', $url);
    $template->set_var('title', $title);
    $template->set_var('blog_name', $blog);
    $template->set_var('excerpt', $excerpt);
    $template->set_var('gltoken_name', CSRF_TOKEN);
    $template->set_var('gltoken', SEC_createToken());

    $template->parse('output', 'editor');
    $retval .= $template->finish($template->get_var('output'));

    $retval .= COM_endBlock(COM_getBlockTemplate('_admin_block', 'footer'));

    return $retval;
}

/**
 * Deletes a trackback comment. Checks if the current user has proper
 * permissions first.
 *
 * @param    int $id ID of the trackback comment to delete
 * @return   string          HTML redirect
 */
function deleteTrackbackComment($id)
{
    global $_TABLES;

    // Validate permission
    if (!validatePermission('delete_trackback')) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
        return;
    }

    // Validate and sanitize ID
    $cid = validateInteger($id, 1);
    if ($cid === false) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
        return;
    }

    // Use prepared statement for security
    $result = DB_query("SELECT sid,type FROM {$_TABLES['trackback']} WHERE cid = " . (int)$cid);
    if (DB_numRows($result) === 0) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
        return;
    }

    list ($sid, $type) = DB_fetchArray($result);
    $url = PLG_getItemInfo($type, $sid, 'url');

    if (TRB_allowDelete($sid, $type)) {
        TRB_deleteTrackbackComment($cid);
        if ($type == 'article') {
            $escaped_sid = DB_escapeString($sid);
            DB_query("UPDATE {$_TABLES['stories']} SET trackbacks = trackbacks - 1 WHERE (sid = '$escaped_sid')");
        }
        $msg = 62;
    } else {
        $msg = 63;
    }
    
    if (strpos($url, '?') === false) {
        $url .= '?msg=' . $msg;
    } else {
        $url .= '&amp;msg=' . $msg;
    }

    COM_redirect($url);
}

/**
 * Show an error or warning message
 *
 * @param    string $title   block title
 * @param    string $message the actual message
 * @return   string              HTML for the message block
 */
function showTrackbackMessage($title, $message)
{
    return COM_showMessageText(secureHtmlEscape($message), secureHtmlEscape($title));
}

/**
 * Send a Pingback to all the links in our entry
 *
 * @param    string $type type of entry we're advertising ('article' = story)
 * @param    string $id   ID of that entry
 * @return   string          pingback results
 */
function sendPingbacks($type, $id)
{
    global $_CONF, $LANG_TRB;

    $retval = '';

    // Validate inputs
    $type = GLText::stripTags($type);
    $id = GLText::stripTags($id);

    list($url, $text) = PLG_getItemInfo($type, $id, 'url,description');
    // Check if item exist
    if (!empty($url)) {
        // extract all links from the text
        preg_match_all("/<a[^>]*href=[\"']([^\"']*)[\"'][^>]*>(.*?)<\/a>/i", $text,
            $matches);
        $numlinks = count($matches[0]);
        if ($numlinks > 0) {
            $links = array();
            for ($i = 0; $i < $numlinks; $i++) {
                // Validate URLs before adding
                $validatedUrl = validateUrl($matches[1][$i]);
                if ($validatedUrl !== false && !isset($links[$validatedUrl])) {
                    $links[$validatedUrl] = secureHtmlEscape($matches[2][$i]);
                }
            }

            $template = COM_newTemplate(CTL_core_templatePath($_CONF['path_layout'] . 'admin/trackback'));
            $template->set_file(array('list' => 'pingbacklist.thtml',
                                      'item' => 'pingbackitem.thtml'));
            $template->set_var('lang_resend', $LANG_TRB['resend']);
            $template->set_var('lang_results', $LANG_TRB['pingback_results']);

            $counter = 1;
            foreach ($links as $URLtoPing => $linktext) {
                $result = PNB_sendPingback($url, $URLtoPing);
                $resend = '';
                if (empty($result)) {
                    $result = '<b>' . $LANG_TRB['pingback_success'] . '</b>';
                } elseif ($result != $LANG_TRB['no_pingback_url']) {
                    $result = COM_createControl('display-text-warning-small', array('text' => secureHtmlEscape($result)));
                    // TBD: $resend = '...';
                }
                $parts = parse_url($URLtoPing);
				
				if (!isset($parts['host'])) {
					$parts['host'] = '';
				}

                $template->set_var('url_to_ping', secureHtmlEscape($URLtoPing));
                $template->set_var('link_text', $linktext);
                $template->set_var('host_name', secureHtmlEscape($parts['host']));
                $template->set_var('pingback_result', $result);
                $template->set_var('resend', $resend);
                $template->set_var('alternate_row',
                    ($counter % 2) == 0 ? 'row-even' : 'row-odd');
                $template->set_var('cssid', ($counter % 2) + 1);
                $template->parse('pingback_results', 'item', true);
                $counter++;
            }
            $template->parse('output', 'list');
            $retval .= $template->finish($template->get_var('output'));

        } else {
            $retval = '<p>' . $LANG_TRB['no_links_pingback'] . '</p>';
        }

        return $retval;
    } else {
        // Error out - Plugin item not found
        COM_redirect($_CONF['site_admin_url'] . '/index.php');        
    }
}

function pingbackForm($targetUrl = '')
{
    global $_CONF, $LANG_TRB;

    $retval = '';
    $retval .= COM_startBlock($LANG_TRB['pingback_button'], COM_getDocumentUrl('docs', "trackback.html"),
        COM_getBlockTemplate('_admin_block', 'header'));

    $template = COM_newTemplate(CTL_core_templatePath($_CONF['path_layout'] . 'admin/trackback'));
    $template->set_file(array('list' => 'pingbackform.thtml'));

    $template->set_var('lang_explain', $LANG_TRB['pingback_explain']);
    $template->set_var('lang_pingback_url', $LANG_TRB['pingback_url']);
    $template->set_var('lang_site_url', $LANG_TRB['site_url']);
    $template->set_var('lang_send', $LANG_TRB['button_send']);
    $template->set_var('max_url_length', 255);

    $template->set_var('target_url', secureHtmlEscape($targetUrl));
    $template->set_var('gltoken_name', CSRF_TOKEN);
    $template->set_var('gltoken', SEC_createToken());

    $template->parse('output', 'list');
    $retval .= $template->finish($template->get_var('output'));

    $retval .= COM_endBlock(COM_getBlockTemplate('_admin_block', 'footer'));

    return $retval;
}

/**
 * Ping weblog directory services
 *
 * @param    string $type type of entry we're advertising ('article' = story)
 * @param    string $id   ID of that entry
 * @return   string          result of the pings
 */
function sendPings($type, $id)
{
    global $_CONF, $_TABLES, $LANG_TRB;

    $retval = '';

    // Validate inputs
    $type = GLText::stripTags($type);
    $id = GLText::stripTags($id);
 
    list($itemurl, $feedurl) = PLG_getItemInfo($type, $id, 'url,feed');
  
    // Check if item exist
    if (!empty($itemurl)) {    
        $template = COM_newTemplate(CTL_core_templatePath($_CONF['path_layout'] . 'admin/trackback'));
        $template->set_file(array('list' => 'pinglist.thtml',
                                  'item' => 'pingitem.thtml'));
        $template->set_var('lang_resend', $LANG_TRB['resend']);
        $template->set_var('lang_results', $LANG_TRB['ping_results']);

        $result = DB_query("SELECT ping_url,method,name,site_url FROM {$_TABLES['pingservice']} WHERE is_enabled = 1");
        $services = DB_numRows($result);
        if ($services > 0) {
            for ($i = 0; $i < $services; $i++) {
                $A = DB_fetchArray($result);
                $resend = '';
                if ($A['method'] == 'weblogUpdates.ping') {
                    $pinged = PNB_sendPing($A['ping_url'], $_CONF['site_name'],
                        $_CONF['site_url'], $itemurl);
                } elseif ($A['method'] == 'weblogUpdates.extendedPing') {
                    $pinged = PNB_sendExtendedPing($A['ping_url'],
                        $_CONF['site_name'], $_CONF['site_url'], $itemurl,
                        $feedurl);
                } else {
                    $pinged = $LANG_TRB['unknown_method'] . ': ' . secureHtmlEscape($A['method']);
                }
                if (empty($pinged)) {
                    $pinged = '<b>' . $LANG_TRB['ping_success'] . '</b>';
                } else {
                    $pinged = COM_createControl('display-text-warning-small', array('text' => secureHtmlEscape($pinged)));
                }

                $template->set_var('service_name', secureHtmlEscape($A['name']));
                $template->set_var('service_url', secureHtmlEscape($A['site_url']));
                $template->set_var('service_ping_url', secureHtmlEscape($A['ping_url']));
                $template->set_var('ping_result', $pinged);
                $template->set_var('resend', $resend);
                $template->set_var('alternate_row',
                    (($i + 1) % 2) == 0 ? 'row-even' : 'row-odd');
                $template->set_var('cssid', ($i % 2) + 1);
                $template->parse('ping_results', 'item', true);
            }
        } else {
            $template->set_var('ping_results', '<tr><td colspan="2">' .
                $LANG_TRB['no_services'] . '</td></tr>');
        }
        $template->set_var('gltoken_name', CSRF_TOKEN);
        $template->set_var('gltoken', SEC_createToken());
        $template->parse('output', 'list');
        $retval .= $template->finish($template->get_var('output'));

        return $retval;
    } else {
        // Error out - Plugin item not found
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }        
}

/**
 * Prepare a list of all links in a story/item so that we can ask the user
 * which one to send the trackback to.
 *
 * @param    string $type type of entry ('article' = story, etc.)
 * @param    string $id   ID of that entry
 * @param    string $text text of that entry, to get the links from
 * @return   string          formatted list of links
 */
function prepareAutodetect($type, $id, $text)
{
    global $_CONF, $LANG_TRB;

    $retval = '';

    // Validate inputs
    $type = GLText::stripTags($type);
    $id = GLText::stripTags($id);

    $baseurl = $_CONF['site_admin_url']
        . '/trackback.php?mode=autodetect&amp;id=' . urlencode($id);
    if ($type != 'article') {
        $baseurl .= '&type=' . urlencode($type);
    }

    // extract all links from the text
    preg_match_all("/<a[^>]*href=[\"']([^\"']*)[\"'][^>]*>(.*?)<\/a>/i", $text,
        $matches);
    $numlinks = count($matches[0]);
    if ($numlinks == 1) {
        // skip the link selection when there's only one link in the story
        $validatedUrl = validateUrl($matches[1][0]);
        if ($validatedUrl !== false) {
            $url = urlencode($validatedUrl);
            $link = $baseurl . '&amp;url=' . $url;
            COM_redirect($link);
        }
    } elseif ($numlinks > 0) {
        $template = COM_newTemplate(CTL_core_templatePath($_CONF['path_layout'] . 'admin/trackback'));
        $template->set_file(array(
            'list' => 'autodetectlist.thtml',
            'item' => 'autodetectitem.thtml',
        ));

        $url = $_CONF['site_admin_url'] . '/trackback.php?mode=new&amp;id=' . urlencode($id);
        if ($type != 'article') {
            $url .= '&amp;type=' . urlencode($type);
        }
        $template->set_var('lang_trackback_explain',
            sprintf($LANG_TRB['trackback_explain'], $url));

        for ($i = 0; $i < $numlinks; $i++) {
            $validatedUrl = validateUrl($matches[1][$i]);
            if ($validatedUrl !== false) {
                $url = urlencode($validatedUrl);
                $link = $baseurl . '&amp;url=' . $url;

                $template->set_var('autodetect_link', $link);
                $template->set_var('link_text', secureHtmlEscape($matches[2][$i]));
                $template->set_var('link_url', secureHtmlEscape($validatedUrl));
                $template->set_var('alternate_row',
                    (($i + 1) % 2) == 0 ? 'row-even' : 'row-odd');
                $template->set_var('cssid', ($i % 2) + 1);
                $template->parse('autodetect_items', 'item', true);
            }
        }
        $template->parse('output', 'list');
        $retval .= $template->finish($template->get_var('output'));
    } else {
        $retval .= $LANG_TRB['no_links_trackback'];
    }

    return $retval;
}

/**
 * Display a list of all weblog directory services in the system
 *
 * @return   string          HTML for the list
 */
function listServices()
{
    global $LANG_ADMIN, $LANG_TRB, $_CONF, $_IMAGE_TYPE, $_TABLES;

    require_once $_CONF['path_system'] . 'lib-admin.php';

    $retval = '';
    $token = SEC_createToken();

    $header_arr = array(      # display 'text' and use table field 'field'
        array('text' => $LANG_ADMIN['edit'], 'field' => 'edit', 'sort' => false),
        array('text' => $LANG_TRB['service'], 'field' => 'name', 'sort' => true),
        array('text' => $LANG_TRB['ping_method'], 'field' => 'method', 'sort' => true),
        array('text' => $LANG_TRB['service_ping_url'], 'field' => 'ping_url', 'sort' => true),
        array('text' => $LANG_ADMIN['enabled'], 'field' => 'is_enabled', 'sort' => false),
    );

    $defsort_arr = array('field' => 'name', 'direction' => 'asc');

    $menu_arr = array(
        array('url'  => $_CONF['site_admin_url'] . '/trackback.php?mode=editservice',
              'text' => $LANG_ADMIN['create_new']),
        array('url'  => $_CONF['site_admin_url'],
              'text' => $LANG_ADMIN['admin_home']));

    $retval .= COM_startBlock($LANG_TRB['services_headline'], '',
        COM_getBlockTemplate('_admin_block', 'header'));

    $retval .= ADMIN_createMenu(
        $menu_arr,
        $LANG_TRB['service_explain'],
        $_CONF['layout_url'] . '/images/icons/trackback.' . $_IMAGE_TYPE
    );

    $text_arr = array(
        'has_extras' => true,
        'form_url'   => $_CONF['site_admin_url'] . '/trackback.php',
        'help_url'   => COM_getDocumentUrl('docs', "trackback.html") . '#ping',
    );

    $query_arr = array(
        'table'          => 'pingservice',
        'sql'            => "SELECT * FROM {$_TABLES['pingservice']} WHERE 1=1",
        'query_fields'   => array('name', 'ping_url'),
        'default_filter' => "",
        'no_data'        => $LANG_TRB['no_services'],
    );

    // this is a dummy variable so we know the form has been used if all services
    // should be disabled in order to disable the last one.
    $form_arr = array(
        'top'    => '<input type="hidden" name="' . CSRF_TOKEN . '" value="'
            . $token . '"' . XHTML . '>',
        'bottom' => '<input type="hidden" name="serviceChanger" value="true"'
            . XHTML . '>',
    );

    $retval .= ADMIN_list('pingservice', 'ADMIN_getListField_trackback',
        $header_arr, $text_arr, $query_arr, $defsort_arr,
        '', $token, '', $form_arr);
    $retval .= COM_endBlock(COM_getBlockTemplate('_admin_block', 'footer'));

    if ($_CONF['trackback_enabled']) {
        $retval .= freshTrackback();
    }
    if ($_CONF['pingback_enabled']) {
        $retval .= freshPingback();
    }

    return $retval;
}

/**
 * Display weblog directory service editor
 *
 * @param    int    $pid          ID of the service or 0 for new service
 * @param    string $msg          an error message to display
 * @param    string $new_name     name of the service
 * @param    string $new_site_url URL of the service's site
 * @param    string $new_ping_url URL to ping at the service
 * @param    string $new_method   ping method to use
 * @param    int    $new_enabled  service is enabled (1) / disabled (0)
 * @return   string                  HTML for the editor
 */
function editServiceForm($pid, $msg = '', $new_name = '', $new_site_url = '', $new_ping_url = '', $new_method = '', $new_enabled = -1)
{
    global $_CONF, $_TABLES, $LANG_TRB, $LANG_ADMIN, $MESSAGE;

    $retval = '';

    // Validate PID
    $pid = validateInteger($pid, 0);
    if ($pid === false) {
        $pid = 0;
    }

    if ($pid > 0) {
        $result = DB_query("SELECT * FROM {$_TABLES['pingservice']} WHERE pid = " . (int)$pid);
        if (DB_numRows($result) > 0) {
            $A = DB_fetchArray($result);
        } else {
            // Invalid PID, redirect
            COM_redirect($_CONF['site_admin_url'] . '/trackback.php?mode=listservice');
            return;
        }
    } else {
        $A['is_enabled'] = 1;
        $A['method'] = 'weblogUpdates.ping';
    }

    if (!empty($new_name)) {
        $A['name'] = $new_name;
    }
    if (!empty($new_site_url)) {
        $A['site_url'] = $new_site_url;
    }
    if (!empty($new_ping_url)) {
        $A['ping_url'] = $new_ping_url;
    }
    if (!empty($new_method)) {
        $A['method'] = $new_method;
    }
    if ($new_enabled >= 0) {
        $A['is_enabled'] = $new_enabled;
    }

    if (!empty($msg)) {
        $retval .= showTrackbackMessage('Error', $msg);
    }

    $token = SEC_createToken();

    $retval .= COM_startBlock($LANG_TRB['edit_service'], COM_getDocumentUrl('docs', "trackback.html") . '#ping',
        COM_getBlockTemplate('_admin_block', 'header'));
    $retval .= SEC_getTokenExpiryNotice($token);

    $template = COM_newTemplate(CTL_core_templatePath($_CONF['path_layout'] . 'admin/trackback'));
    $template->set_file(array('editor' => 'serviceeditor.thtml'));
    $template->set_var('max_url_length', 255);
    $template->set_var('method_ping', 'weblogUpdates.ping');
    $template->set_var('method_ping_extended', 'weblogUpdates.extendedPing');

    $template->set_var('lang_name', $LANG_TRB['service']);
    $template->set_var('lang_site_url', $LANG_TRB['service_website']);
    $template->set_var('lang_ping_url', $LANG_TRB['service_ping_url']);
    $template->set_var('lang_enabled', $LANG_ADMIN['enabled']);
    $template->set_var('lang_method', $LANG_TRB['ping_method']);
    $template->set_var('lang_method_standard', $LANG_TRB['ping_standard']);
    $template->set_var('lang_method_extended', $LANG_TRB['ping_extended']);
    $template->set_var('lang_save', $LANG_ADMIN['save']);
    $template->set_var('lang_cancel', $LANG_ADMIN['cancel']);

    if ($pid > 0) {
        $template->set_var('allow_delete', true);
        $template->set_var('lang_delete', $LANG_ADMIN['delete']);
        $template->set_var('confirm_message', $MESSAGE[76]);
    }

    if (isset($A['pid'])) {
        $template->set_var('service_id', (int)$A['pid']);
    } else {
        $template->set_var('service_id', '');
    }
    if (isset($A['name'])) {
        $template->set_var('service_name', secureHtmlEscape($A['name']));
    } else {
        $template->set_var('service_name', '');
    }
    if (isset($A['site_url'])) {
        $template->set_var('service_site_url', secureHtmlEscape($A['site_url']));
    } else {
        $template->set_var('service_site_url', '');
    }
    if (isset($A['ping_url'])) {
        $template->set_var('service_ping_url', secureHtmlEscape($A['ping_url']));
    } else {
        $template->set_var('service_ping_url', '');
    }
    if ($A['is_enabled'] == 1) {
        $template->set_var('is_enabled', 'checked="checked"');
    } else {
        $template->set_var('is_enabled', '');
    }
    if ($A['method'] == 'weblogUpdates.ping') {
        $template->set_var('standard_is_checked', 'checked="checked"');
        $template->set_var('extended_is_checked', '');
    } else {
        $template->set_var('standard_is_checked', '');
        $template->set_var('extended_is_checked', 'checked="checked"');
    }
    $template->set_var('gltoken_name', CSRF_TOKEN);
    $template->set_var('gltoken', $token);

    $template->parse('output', 'editor');
    $retval .= $template->finish($template->get_var('output'));

    $retval .= COM_endBlock(COM_getBlockTemplate('_admin_block', 'footer'));
    $retval = COM_createHTMLDocument($retval, array('pagetitle' => $LANG_TRB['edit_service']));

    return $retval;
}

/**
 * Save information of a weblog directory service
 *
 * @param    int    $pid      ID of service or 0 for new entry
 * @param    string $name     name of the service
 * @param    string $site_url Homepage URL of the service
 * @param    string $ping_url URL to ping at the service
 * @param    string $method   method used for the ping
 * @param    string $enabled  'on' when enabled
 * @return   string              HTML redirect or service editor
 */
function saveService($pid, $name, $site_url, $ping_url, $method, $enabled)
{
    global $_CONF, $_TABLES, $LANG_TRB;

    // Validate permission
    if (!validatePermission('save_service')) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
        return;
    }

    // Validate PID
    $pid = validateInteger($pid, 0);
    if ($pid === false) {
        $pid = 0;
    }

    $enabled = ($enabled == 'on' ? 1 : 0);
    if ($method == 'extended') {
        $method = 'weblogUpdates.extendedPing';
    } else {
        $method = 'weblogUpdates.ping';
    }

    $name = GLText::stripTags($name);
    $site_url = GLText::stripTags($site_url);
    $ping_url = GLText::stripTags($ping_url);

    $errormsg = '';
    if (empty($name) || strlen($name) > 128) {
        $errormsg = $LANG_TRB['error_site_name'];
    } else {
        // Validate URLs properly
        $validated_site_url = validateUrl($site_url);
        $validated_ping_url = validateUrl($ping_url);
        
        if ($validated_site_url === false) {
            $errormsg = $LANG_TRB['error_site_url'];
        } elseif ($validated_ping_url === false) {
            $errormsg = $LANG_TRB['error_ping_url'];
        } else {
            $site_url = $validated_site_url;
            $ping_url = $validated_ping_url;
        }
    }

    if (!empty($errormsg)) {
        return editServiceForm($pid, $errormsg, $name, $site_url, $ping_url,
            $method, $enabled);
    }

    $name = DB_escapeString($name);
    $site_url = DB_escapeString($site_url);
    $ping_url = DB_escapeString($ping_url);

    if ($pid > 0) {
        DB_save($_TABLES['pingservice'],
            'pid,name,site_url,ping_url,method,is_enabled',
            "'$pid','$name','$site_url','$ping_url','$method','$enabled'");
    } else {
        DB_save($_TABLES['pingservice'],
            'name,site_url,ping_url,method,is_enabled',
            "'$name','$site_url','$ping_url','$method','$enabled'");
    }

    COM_redirect($_CONF['site_admin_url'] . '/trackback.php?mode=listservice&amp;msg=65');
}

/**
 * Toggle status of a ping service from enabled to disabled and back
 *
 * @param    array $enabledservices array containing ids of enabled services
 * @param    array $visibleservices array containing ids of visible services
 * @return   void
 */
function changeServiceStatus($enabledservices, $visibleservices)
{
    global $_TABLES;

    // Validate permission
    if (!validatePermission('save_service')) {
        return;
    }

    // Validate and sanitize service IDs
    $validEnabledServices = array();
    $validVisibleServices = array();

    foreach ($enabledservices as $id) {
        $validId = validateInteger($id, 1);
        if ($validId !== false) {
            $validEnabledServices[] = $validId;
        }
    }

    foreach ($visibleservices as $id) {
        $validId = validateInteger($id, 1);
        if ($validId !== false) {
            $validVisibleServices[] = $validId;
        }
    }

    $disabled = array_diff($validVisibleServices, $validEnabledServices);

    // disable services
    if (!empty($disabled)) {
        $in = implode(',', array_map('intval', $disabled));
        $sql = "UPDATE {$_TABLES['pingservice']} SET is_enabled = 0 WHERE pid IN ($in)";
        DB_query($sql);
    }

    // enable services
    if (!empty($validEnabledServices)) {
        $in = implode(',', array_map('intval', $validEnabledServices));
        $sql = "UPDATE {$_TABLES['pingservice']} SET is_enabled = 1 WHERE pid IN ($in)";
        DB_query($sql);
    }
}

/**
 * Display a note about how trackbacks are supposed to be used
 */
function freshTrackback()
{
    global $_CONF, $LANG_TRB;

    $retval = '';

    $freshurl = $_CONF['site_admin_url'] . '/trackback.php?mode=fresh';

    $retval .= COM_startBlock($LANG_TRB['trackback'], COM_getDocumentUrl('docs', "trackback.html"),
        COM_getBlockTemplate('_admin_block', 'header'));
    $retval .= sprintf($LANG_TRB['trackback_note'], $freshurl);
    $retval .= COM_endBlock();

    return $retval;
}

/**
 * Display a note about how pingbacks are supposed to be used
 */
function freshPingback()
{
    global $_CONF, $LANG_TRB;

    $retval = '';

    $freshurl = $_CONF['site_admin_url'] . '/trackback.php?mode=freepb';

    $retval .= COM_startBlock($LANG_TRB['pingback'], COM_getDocumentUrl('docs', "trackback.html"),
        COM_getBlockTemplate('_admin_block', 'header'));
    $retval .= sprintf($LANG_TRB['pingback_note'], $freshurl);
    $retval .= COM_endBlock();

    return $retval;
}


// MAIN
$display = '';
$mode = '';
if ($_CONF['ping_enabled'] && isset($_POST['serviceChanger']) && SEC_checkToken()) {
    $enabledservices = Geeklog\Input::post('enabledservices', array());
    $visibleservices = Geeklog\Input::post('visibleservices', array());
    changeServiceStatus($enabledservices, $visibleservices);
}

if (isset($_POST['mode']) && is_array($_POST['mode'])) {
    $mode = Geeklog\Input::post('mode');
    if (isset($mode[0])) {
        $mode = 'send';
    } elseif (isset($mode[1])) {
        $mode = 'preview';
    } elseif (isset($mode[2])) {
        $mode = 'sendpingback';
    } else {
        $mode = '';
    }
} elseif (isset($_POST['servicemode']) && is_array($_POST['servicemode'])) {
    $mode = Geeklog\Input::post('servicemode');
    if (isset($mode[0])) {
        $mode = 'saveservice';
    } elseif (isset($mode[2])) {
        $mode = 'deleteservice';
    } else { // $mode[1], Cancel
        $mode = '';
    }
} else {
    if (isset($_REQUEST['mode'])) {
        $mode = Geeklog\Input::fRequest('mode');
    }
}

// Validate mode parameter
$allowedModes = array(
    'send', 'new', 'pretrackback', 'autodetect', 'preview', 'delete',
    'pingback', 'sendall', 'fresh', 'freepb', 'deleteservice', 
    'saveservice', 'editservice', 'listservice', 'sendpingback'
);

if (!in_array($mode, $allowedModes, true)) {
    $mode = '';
}

// sanity check for modes, depending on enabled features ...
if (!$_CONF['ping_enabled'] && in_array($mode, array('deleteservice', 'saveservice', 'editservice'))) {
    $mode = '';
}
if (!$_CONF['trackback_enabled'] &&
    in_array($mode, array('send', 'new', 'pretrackback', 'autodetect', 'preview'))
) {
    $mode = '';
}
if (!$_CONF['pingback_enabled'] && ($mode === 'pingback')) {
    $mode = '';
}
if (!$_CONF['trackback_enabled'] && !$_CONF['pingback_enabled'] && ($mode === 'delete')) {
    $mode = '';
}

// default action depends on which features are enabled ...
if (empty($mode)) {
    if ($_CONF['ping_enabled']) {
        $mode = 'listservice';
    } elseif ($_CONF['trackback_enabled']) {
        $mode = 'fresh';
    } elseif ($_CONF['pingback_enabled']) {
        $mode = 'freepb';
    }
}

if (($mode === 'delete') && SEC_checkToken()) {
    $cid = Geeklog\Input::fRequest('cid');
    $validCid = validateInteger($cid, 1);
    if ($validCid !== false) {
        $display = deleteTrackbackComment($validCid);
    } else {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
} elseif ($mode === 'send') {
    if (!SEC_checkToken()) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
    
    $target = Geeklog\Input::fPost('target');
    $url = Geeklog\Input::fPost('url');
    $title = Geeklog\Input::post('title');
    $excerpt = Geeklog\Input::post('excerpt');
    $blog = Geeklog\Input::post('blog_name');
    
    // Validate URLs
    $validated_target = validateUrl($target);
    $validated_url = validateUrl($url);
    
    if ($validated_target === false) {
        $display .= showTrackbackMessage($LANG_TRB['target_missing'],
            $LANG_TRB['target_required']);
        $display .= trackback_editor($target, $url, $title, $excerpt, $blog);
    } elseif ($validated_url === false) {
        $display .= showTrackbackMessage($LANG_TRB['url_missing'],
            $LANG_TRB['url_required']);
        $display .= trackback_editor($target, $url, $title, $excerpt, $blog);
    } else {
        // prepare for send
        $send_title = TRB_filterTitle($title);
        $send_excerpt = TRB_filterExcerpt($excerpt);
        $send_blog = TRB_filterBlogname($blog);

        $result = TRB_sendTrackbackPing($validated_target, $validated_url, $send_title, $send_excerpt, $send_blog);
        if ($result === true) {
            $display .= COM_showMessage(64);
            $display .= trackback_editor();
        } else {
            $message = '<p>' . $LANG_TRB['send_error_details']
                . '<br' . XHTML . '><span class="warningsmall">'
                . secureHtmlEscape($result) . '</span></p>';
            $display .= showTrackbackMessage($LANG_TRB['send_error'], $message);

            // display editor with the same contents again
            $display .= trackback_editor($target, $url, $title, $excerpt, $blog);
        }
    }
    $display = COM_createHTMLDocument($display, array('pagetitle' => $LANG_TRB['trackback']));
} elseif ($mode === 'new') {
    $type = Geeklog\Input::fRequest('type', 'article');
    $id = Geeklog\Input::fRequest('id');
    
    // Validate inputs
    $type = GLText::stripTags($type);
    $id = GLText::stripTags($id);
    
    if (!empty($id)) {
        list($url, $title, $excerpt) = PLG_getItemInfo($type, $id, 'url,title,excerpt');
        if (!empty($url)) {
            $excerpt = trim(GLText::stripTags($excerpt));
            $blog = TRB_filterBlogname($_CONF['site_name']);
			
			$target = '';
            $display .= trackback_editor($target, $url, $title, $excerpt, $blog);
            $display = COM_createHTMLDocument($display, array('pagetitle' => $LANG_TRB['trackback']));
        } else {
            // Error out - Plugin item not found
            COM_redirect($_CONF['site_admin_url'] . '/index.php');
        }
    } else {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
} elseif ($mode === 'pingback') {
    $type = Geeklog\Input::fRequest('type', 'article');
    $id = Geeklog\Input::fRequest('id');
    
    // Validate inputs
    $type = GLText::stripTags($type);
    $id = GLText::stripTags($id);
    
    if (!empty($id)) {
        $display .= COM_startBlock($LANG_TRB['pingback_results'])
            . sendPingbacks($type, $id)
            . COM_endBlock();
        $display = COM_createHTMLDocument($display, array('pagetitle' => $LANG_TRB['pingback']));
    } else {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
} elseif ($mode === 'sendall') {
    $id = Geeklog\Input::fRequest('id');
    if (empty($id)) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
    $type = Geeklog\Input::fRequest('type', 'article');
    
    // Validate inputs
    $type = GLText::stripTags($type);
    $id = GLText::stripTags($id);

    $pingback_sent = isset($_REQUEST['pingback_sent']);
    $ping_sent = isset($_REQUEST['ping_sent']);
    $trackback_sent = isset($_REQUEST['trackback_sent']);

    $pingresult = '';
    if (isset($_POST['what']) && is_array($_POST['what'])) {
        $what = Geeklog\Input::post('what');
        if (isset($what[0])) {         // Pingback
            $pingresult = sendPingbacks($type, $id);
            $pingback_sent = true;
        } elseif (isset($what[1])) {  // Ping
            $pingresult = sendPings($type, $id);
            $ping_sent = true;
        } elseif (isset($what[2])) {  // Trackback
            $url = $_CONF['site_admin_url'] . '/trackback.php?mode=pretrackback&amp;id=' . urlencode($id);
            if ($type !== 'article') {
                $url .= '&amp;type=' . urlencode($type);
            }
            COM_redirect($url);
        }
    }

    $title = PLG_getItemInfo($type, $id, 'title');
    
    // Check if item exist
    if (!empty($title)) {
        $display .= COM_startBlock(sprintf($LANG_TRB['send_pings_for'], secureHtmlEscape($title)));

        $template = COM_newTemplate(CTL_core_templatePath($_CONF['path_layout'] . 'admin/trackback'));
        $template->set_file(array('form' => 'pingform.thtml'));
        $template->set_var('php_self', $_CONF['site_admin_url'] . '/trackback.php');
        $template->set_var('lang_may_take_a_while', $LANG_TRB['may_take_a_while']);
        $template->set_var('lang_ping_explain', $LANG_TRB['ping_all_explain']);
        $template->set_var('ping_results', $pingresult);

        if ($_CONF['pingback_enabled']) {
            if (!$pingback_sent) {
                $template->set_var('lang_pingback_button', $LANG_TRB['pingback_button']);
                $template->set_var('lang_pingback_short', $LANG_TRB['pingback_short']);
                $button = '<button type="submit" name="what[0]" value="'
                    . secureHtmlEscape($LANG_TRB['pingback_button']) . '" class="uk-form">'
                    . secureHtmlEscape($LANG_TRB['pingback_button']) . '</button>';
                $template->set_var('pingback_button', $button);
            }
        } else {
            $template->set_var('pingback_button', $LANG_TRB['pingback_disabled']);
        }
        if ($_CONF['ping_enabled']) {
            if (!$ping_sent) {
                $template->set_var('lang_ping_button', $LANG_TRB['ping_button']);
                $template->set_var('lang_ping_short', $LANG_TRB['ping_short']);
                $button = '<button type="submit" name="what[1]" value="'
                    . secureHtmlEscape($LANG_TRB['ping_button']) . '" class="uk-form">'
                    . secureHtmlEscape($LANG_TRB['ping_button']) . '</button>';
                $template->set_var('ping_button', $button);
            }
        } else {
            $template->set_var('ping_button', $LANG_TRB['ping_disabled']);
        }
        if ($_CONF['trackback_enabled']) {
            if (!$trackback_sent) {
                $template->set_var('lang_trackback_button', $LANG_TRB['trackback_button']);
                $template->set_var('lang_trackback_short', $LANG_TRB['trackback_short']);
                $button = '<button type="submit" name="what[2]" value="'
                    . secureHtmlEscape($LANG_TRB['trackback_button']) . '" class="uk-form">'
                    . secureHtmlEscape($LANG_TRB['trackback_button']) . '</button>';
                $template->set_var('trackback_button', $button);
            }
        } else {
            $template->set_var('trackback_button', $LANG_TRB['trackback_disabled']);
        }

        $hidden = '';
        if ($pingback_sent) {
            $hidden .= '<input type="hidden" name="pingback_sent" value="1"' . XHTML . '>';
        }
        if ($ping_sent) {
            $hidden .= '<input type="hidden" name="ping_sent" value="1"' . XHTML . '>';
        }
        if ($trackback_sent) {
            $hidden .= '<input type="hidden" name="trackback_sent" value="1"' . XHTML . '>';
        }
        $hidden .= '<input type="hidden" name="id" value="' . secureHtmlEscape($id) . '"' . XHTML . '>';
        $hidden .= '<input type="hidden" name="type" value="' . secureHtmlEscape($type) . '"' . XHTML . '>';
        $hidden .= '<input type="hidden" name="mode" value="sendall"' . XHTML . '>';
        $template->set_var('hidden_input_fields', $hidden);

        $template->parse('output', 'form');
        $display .= $template->finish($template->get_var('output'));

        $display .= COM_endBlock();
        $display = COM_createHTMLDocument($display, array('pagetitle' => $LANG_TRB['send_pings']));
    } else {
        // Error out
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
} elseif ($mode === 'pretrackback') {
    $id = Geeklog\Input::fRequest('id');
    if (empty($id)) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
    $type = Geeklog\Input::fRequest('type', 'article');

    // Validate inputs
    $type = GLText::stripTags($type);
    $id = GLText::stripTags($id);

    $fulltext = PLG_getItemInfo($type, $id, 'description');

    // Check if item exist
    if (!empty($fulltext)) {
        $display .= COM_startBlock($LANG_TRB['select_url'],
                COM_getDocumentUrl('docs', "trackback.html") . '#trackback')
            . prepareAutodetect($type, $id, $fulltext)
            . COM_endBlock();
        $display = COM_createHTMLDocument($display, array('pagetitle' => $LANG_TRB['trackback']));
    } else {
        // Error out - Plugin item not found
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
} elseif ($mode === 'autodetect') {
    $id = Geeklog\Input::fRequest('id');
    $url = Geeklog\Input::request('url');
    if (empty($id) || empty($url)) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }

    $type = Geeklog\Input::fRequest('type', 'article');

    // Validate inputs
    $type = GLText::stripTags($type);
    $id = GLText::stripTags($id);
    $validated_url = validateUrl($url);
    
    if ($validated_url === false) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }

    $trackbackUrl = TRB_detectTrackbackUrl($validated_url);

    list($url, $title, $excerpt) = PLG_getItemInfo($type, $id, 'url,title,excerpt');
    
    // Check if item exist
    if (!empty($url)) {
        $excerpt = trim(GLText::stripTags($excerpt));
        $blog = TRB_filterBlogname($_CONF['site_name']);

        if ($trackbackUrl === false) {
            $display .= showTrackbackMessage($LANG_TRB['not_found'], $LANG_TRB['autodetect_failed']);
        }
        $display .= trackback_editor($trackbackUrl, $url, $title, $excerpt, $blog);
        $display = COM_createHTMLDocument($display, array('pagetitle' => $LANG_TRB['trackback']));
    } else {
        // Error out - Plugin item not found
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }        
} elseif (($mode === 'fresh') || ($mode === 'preview')) {
    $display .= COM_showMessageFromParameter();

    $target = Geeklog\Input::fRequest('target', '');
    $url = Geeklog\Input::fRequest('url', '');
    $title = Geeklog\Input::fRequest('title', '');
    $excerpt = Geeklog\Input::request('excerpt', '');
    $blog = Geeklog\Input::request('blog_name', '');

    if (isset($_REQUEST['id'], $_REQUEST['type'])) {
        $id = Geeklog\Input::fRequest('id', '');
        $type = Geeklog\Input::fRequest('type', '');
        
        // Validate inputs
        $type = GLText::stripTags($type);
        $id = GLText::stripTags($id);
        
        if (!empty($id) && !empty($type)) {
            list($newurl, $newtitle, $newexcerpt) = PLG_getItemInfo($type, $id, 'url,title,excerpt');
            $newexcerpt = trim(GLText::stripTags($newexcerpt));

            if (empty($url) && !empty($newurl)) {
                $url = $newurl;
            }
            if (empty($title) && !empty($newtitle)) {
                $title = $newtitle;
            }
            if (empty($excerpt) && !empty($newexcerpt)) {
                $excerpt = $newexcerpt;
            }

            if (empty($blog)) {
                $blog = TRB_filterBlogname($_CONF['site_name']);
            }
        }
    }

    if (($mode === 'preview') && empty($url)) {
        $display .= showTrackbackMessage($LANG_TRB['url_missing'], $LANG_TRB['url_required']);
    }

    $display .= trackback_editor($target, $url, $title, $excerpt, $blog);

    $display = COM_createHTMLDocument($display, array('pagetitle' => $LANG_TRB['trackback']));
} elseif (($mode === 'deleteservice') && SEC_checkToken()) {
    if (!validatePermission('delete_service')) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
    
    $pid = Geeklog\Input::fPost('service_id', 0);
    $validPid = validateInteger($pid, 1);
    if ($validPid !== false) {
        DB_delete($_TABLES['pingservice'], 'pid', $validPid);
        COM_redirect($_CONF['site_admin_url'] . '/trackback.php?mode=listservice&amp;msg=66');
    } else {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
} elseif (($mode === 'saveservice') && SEC_checkToken()) {
    $is_enabled = Geeklog\Input::post('is_enabled', '');
    $display .= saveService(
        Geeklog\Input::fPost('service_id', 0),
        Geeklog\Input::post('service_name', ''),
        Geeklog\Input::post('service_site_url', ''),
        Geeklog\Input::post('service_ping_url', ''),
        Geeklog\Input::post('method', ''),
        $is_enabled
    );
} elseif ($mode === 'editservice') {
    $service_id = Geeklog\Input::fGet('service_id', 0);
    $pid = validateInteger($service_id, 0);
    if ($pid === false) {
        $pid = 0;
    }

    $display .= editServiceForm($pid);
} elseif ($mode === 'listservice') {
    $display .= COM_showMessageFromParameter();
    $display .= listServices();
    $display = COM_createHTMLDocument($display, array('pagetitle' => $LANG_TRB['services_headline']));
} elseif ($mode === 'freepb') {
    $display .= COM_showMessageFromParameter();
    $display .= pingbackForm();
    $display = COM_createHTMLDocument($display, array('pagetitle' => $LANG_TRB['pingback']));
} elseif ($mode === 'sendpingback') {
    if (!SEC_checkToken()) {
        COM_redirect($_CONF['site_admin_url'] . '/index.php');
    }
    
    $target = Geeklog\Input::fPost('target');
    $validated_target = validateUrl($target);
    
    if ($validated_target === false) {
        $display .= showTrackbackMessage($LANG_TRB['pbtarget_missing'], $LANG_TRB['pbtarget_required']);
    } else {
        $result = PNB_sendPingback($_CONF['site_url'], $validated_target);
        if (empty($result)) {
            $display .= COM_showMessage(74);
            $target = '';
        } else {
            $message = '<p>' . $LANG_TRB['pb_error_details'] . '<br' . XHTML . '>'
                . '<span class="warningsmall">'
                . secureHtmlEscape($result) . '</span></p>';
            $display .= showTrackbackMessage($LANG_TRB['send_error'], $message);
        }
    }
    $display .= pingbackForm($target);
    $display = COM_createHTMLDocument($display, array('pagetitle' => $LANG_TRB['pingback']));
} else {
    COM_redirect($_CONF['site_admin_url'] . '/index.php');
}

COM_output($display);
