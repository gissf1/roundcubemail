<?php

// ini_set('error_reporting', -1 & ~E_NOTICE);
// ini_set('display_errors', 1);


if (false) {
	define('VARDUMP', 'var_dump');
} else {
	function VARDUMP() {}
}

function debugmsg($msg) {
	$args = func_get_args();
	if ($msg && empty($args)) {
		debug_print_backtrace();
		ob_end_flush();
		var_dump($msg);
	} elseif ($msg && $args) {
		echo '<table border=0><tr><td><pre>';
			debug_print_backtrace();
			ob_end_flush();
		echo '</pre></td></tr><tr><td>';
		echo htmlentities($msg);
		echo '</td><td>';
		var_dump($args);
		echo '</td></tr></table>';
	}
	flush();
}

function getImapStr($str) {
	if ($str == '') return '""';
	$str = '{' . strlen($str) . "}\r\n$str";
	return $str;
}

/**
 * PHP based wrapper class to connect to an IMAP server
 *
 * @package    Framework
 * @subpackage Storage
 */
class imap_custom extends rcube_imap_generic
{
    /**
     * Object constructor
     */
    function __construct()
    {
		stream_wrapper_register("customimap", "ImapCustomStream")
			or die("Failed to register protocol");
    }

    function __destruct() {
		///TODO: unregister customimap
    }

    /**
     * Closes connection stream.
     */
    protected function closeSocket()
    {
        $this->fp = null;
    }

    /**
     * Connects to IMAP server.
     *
     * @param string $host Server hostname or IP
     *
     * @return bool True on success, False on failure
     */
    protected function _connect($host)
    {
        // initialize connection
        $this->error    = '';
        $this->errornum = self::ERROR_OK;

        if (!$this->prefs['port']) {
            $this->prefs['port'] = 143;
        }

        // check for SSL
        if ($this->prefs['ssl_mode'] && $this->prefs['ssl_mode'] != 'tls') {
            $host = $this->prefs['ssl_mode'] . '://' . $host;
        }

        if ($this->prefs['timeout'] <= 0) {
            $this->prefs['timeout'] = max(0, intval(ini_get('default_socket_timeout')));
        }

//         if (!empty($this->prefs['socket_options'])) {
//             $context  = stream_context_create($this->prefs['socket_options']);
//             $this->fp = stream_socket_client($host . ':' . $this->prefs['port'], $errno, $errstr,
//                 $this->prefs['timeout'], STREAM_CLIENT_CONNECT, $context);
//         }
//         else {
//             $this->fp = @fsockopen($host, $this->prefs['port'], $errno, $errstr, $this->prefs['timeout']);
//         }
		$this->fp = fopen("customimap://$host/", "r+");

        if (!$this->fp) {
            $this->setError(self::ERROR_BAD, sprintf("Could not connect to %s:%d: %s",
                $host, $this->prefs['port'], $errstr ?: "Unknown reason"));

            return false;
        }

        if ($this->prefs['timeout'] > 0) {
            stream_set_timeout($this->fp, $this->prefs['timeout']);
        }

        $line = trim(fgets($this->fp, 8192));
VARDUMP($line);

        if ($this->_debug) {
            // set connection identifier for debug output
            preg_match('/#([0-9]+)/', (string) $this->fp, $m);
            $this->resourceid = strtoupper(substr(md5($m[1].$this->user.microtime()), 0, 4));

            if ($line) {
                $this->debug('S: '. $line);
            }
        }

        // Connected to wrong port or connection error?
        if (!preg_match('/^\* (OK|PREAUTH)/i', $line)) {
            if ($line)
                $error = sprintf("Wrong startup greeting (%s:%d): %s", $host, $this->prefs['port'], $line);
            else
                $error = sprintf("Empty startup greeting (%s:%d)", $host, $this->prefs['port']);

            $this->setError(self::ERROR_BAD, $error);
            $this->closeConnection();
            return false;
        }

        // RFC3501 [7.1] optional CAPABILITY response
        if (preg_match('/\[CAPABILITY ([^]]+)\]/i', $line, $matches)) {
            $this->parseCapability($matches[1], true);
        }

        // TLS connection
        if ($this->prefs['ssl_mode'] == 'tls' && $this->getCapability('STARTTLS')) {
            $res = $this->execute('STARTTLS');

            if ($res[0] != self::ERROR_OK) {
                $this->closeConnection();
                return false;
            }

            if (isset($this->prefs['socket_options']['ssl']['crypto_method'])) {
                $crypto_method = $this->prefs['socket_options']['ssl']['crypto_method'];
            }
            else {
                // There is no flag to enable all TLS methods. Net_SMTP
                // handles enabling TLS similarly.
                $crypto_method = STREAM_CRYPTO_METHOD_TLS_CLIENT
                    | @STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT
                    | @STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            }

            if (!stream_socket_enable_crypto($this->fp, true, $crypto_method)) {
                $this->setError(self::ERROR_BAD, "Unable to negotiate TLS");
                $this->closeConnection();
                return false;
            }

            // Now we're secure, capabilities need to be reread
            $this->clearCapability();
        }

        return true;
    }

    /**
     * FETCH command (RFC3501)
     *
     * @param string $mailbox     Mailbox name
     * @param mixed  $message_set Message(s) sequence identifier(s) or UID(s)
     * @param bool   $is_uid      True if $message_set contains UIDs
     * @param array  $query_items FETCH command data items
     * @param string $mod_seq     Modification sequence for CHANGEDSINCE (RFC4551) query
     * @param bool   $vanished    Enables VANISHED parameter (RFC5162) for CHANGEDSINCE query
     *
     * @return array List of rcube_message_header elements, False on error
     * @since 0.6
     */
    function fetch($mailbox, $message_set, $is_uid = false, $query_items = array(),
        $mod_seq = null, $vanished = false)
    {
        if (!$this->select($mailbox)) {
            return false;
        }

        $message_set = $this->compressMessageSet($message_set);
        $result      = array();

        $key      = $this->nextTag();
        $request  = $key . ($is_uid ? ' UID' : '') . " FETCH $message_set ";
        $request .= "(" . implode(' ', $query_items) . ")";

        if ($mod_seq !== null && $this->hasCapability('CONDSTORE')) {
            $request .= " (CHANGEDSINCE $mod_seq" . ($vanished ? " VANISHED" : '') .")";
        }

        if (!$this->putLine($request)) {
            $this->setError(self::ERROR_COMMAND, "Unable to send command: $request");
            return false;
        }

        do {
            $line = $this->readLine(4096);

            if (!$line)
                break;

            // Sample reply line:
            // * 321 FETCH (UID 2417 RFC822.SIZE 2730 FLAGS (\Seen)
            // INTERNALDATE "16-Nov-2008 21:08:46 +0100" BODYSTRUCTURE (...)
            // BODY[HEADER.FIELDS ...

            if (preg_match('/^\* ([0-9]+) FETCH/', $line, $m)) {
                $id = intval($m[1]);

                $result[$id]            = new rcube_message_header;
                $result[$id]->id        = $id;
                $result[$id]->subject   = '';
                $result[$id]->messageID = 'mid:' . $id;

                $headers = null;
                $lines   = array();
                $line    = substr($line, strlen($m[0]) + 2);
                $ln      = 0;

                // get complete entry
                while (preg_match('/\{([0-9]+)\}\r\n$/', $line, $m)) {
                    $bytes = $m[1];
                    $out   = '';

                    while (strlen($out) < $bytes) {
                        $out = $this->readBytes($bytes);
                        if ($out === NULL)
                            break;
                        $line .= $out;
                    }

                    $str = $this->readLine(4096);
                    if ($str === false)
                        break;

                    $line .= $str;
                }

                // Tokenize response and assign to object properties
                while (list($name, $value) = $this->tokenizeResponse($line, 2)) {
                    if ($name == 'UID') {
                        $result[$id]->uid = intval($value);
                    }
                    else if ($name == 'RFC822.SIZE') {
                        $result[$id]->size = intval($value);
                    }
                    else if ($name == 'RFC822.TEXT') {
                        $result[$id]->body = $value;
                    }
                    else if ($name == 'INTERNALDATE') {
                        $result[$id]->internaldate = $value;
                        $result[$id]->date         = $value;
                        $result[$id]->timestamp    = $this->StrToTime($value);
                    }
                    else if ($name == 'FLAGS') {
                        if (!empty($value)) {
                            foreach ((array)$value as $flag) {
                                $flag = str_replace(array('$', '\\'), '', $flag);
                                $flag = strtoupper($flag);

                                $result[$id]->flags[$flag] = true;
                            }
                        }
                    }
                    else if ($name == 'MODSEQ') {
                        $result[$id]->modseq = $value[0];
                    }
                    else if ($name == 'ENVELOPE') {
                        $result[$id]->envelope = $value;
                    }
                    else if ($name == 'BODYSTRUCTURE' || ($name == 'BODY' && count($value) > 2)) {
                        if (!is_array($value[0]) && (strtolower($value[0]) == 'message' && strtolower($value[1]) == 'rfc822')) {
                            $value = array($value);
                        }
                        $result[$id]->bodystructure = $value;
                    }
                    else if ($name == 'RFC822') {
                        $result[$id]->body = $value;
                    }
                    else if (stripos($name, 'BODY[') === 0) {
                        $name = str_replace(']', '', substr($name, 5));

                        if ($name == 'HEADER.FIELDS') {
                            // skip ']' after headers list
                            $this->tokenizeResponse($line, 1);
                            $headers = $this->tokenizeResponse($line, 1);
                        }
                        else if (strlen($name))
                            $result[$id]->bodypart[$name] = $value;
                        else
                            $result[$id]->body = $value;
                    }
                }

                // create array with header field:data
                if (!empty($headers)) {
                    $headers = explode("\n", trim($headers));
                    foreach ($headers as $resln) {
                        if (ord($resln[0]) <= 32) {
                            $lines[$ln] .= (empty($lines[$ln]) ? '' : "\n") . trim($resln);
                        } else {
                            $lines[++$ln] = trim($resln);
                        }
                    }

                    foreach ($lines as $str) {
                        list($field, $string) = explode(':', $str, 2);

                        $field  = strtolower($field);
                        $string = preg_replace('/\n[\t\s]*/', ' ', trim($string));

                        switch ($field) {
                        case 'date';
                            $result[$id]->date = $string;
                            $result[$id]->timestamp = $this->strToTime($string);
                            break;
                        case 'from':
                            $result[$id]->from = $string;
                            break;
                        case 'to':
                            $result[$id]->to = preg_replace('/undisclosed-recipients:[;,]*/', '', $string);
                            break;
                        case 'subject':
                            $result[$id]->subject = $string;
                            break;
                        case 'reply-to':
                            $result[$id]->replyto = $string;
                            break;
                        case 'cc':
                            $result[$id]->cc = $string;
                            break;
                        case 'bcc':
                            $result[$id]->bcc = $string;
                            break;
                        case 'content-transfer-encoding':
                            $result[$id]->encoding = $string;
                        break;
                        case 'content-type':
                            $ctype_parts = preg_split('/[; ]+/', $string);
                            $result[$id]->ctype = strtolower(array_shift($ctype_parts));
                            if (preg_match('/charset\s*=\s*"?([a-z0-9\-\.\_]+)"?/i', $string, $regs)) {
                                $result[$id]->charset = $regs[1];
                            }
                            break;
                        case 'in-reply-to':
                            $result[$id]->in_reply_to = str_replace(array("\n", '<', '>'), '', $string);
                            break;
                        case 'references':
                            $result[$id]->references = $string;
                            break;
                        case 'return-receipt-to':
                        case 'disposition-notification-to':
                        case 'x-confirm-reading-to':
                            $result[$id]->mdn_to = $string;
                            break;
                        case 'message-id':
                            $result[$id]->messageID = $string;
                            break;
                        case 'x-priority':
                            if (preg_match('/^(\d+)/', $string, $matches)) {
                                $result[$id]->priority = intval($matches[1]);
                            }
                            break;
                        default:
                            if (strlen($field) < 3) {
                                break;
                            }
                            if ($result[$id]->others[$field]) {
                                $string = array_merge((array)$result[$id]->others[$field], (array)$string);
                            }
                            $result[$id]->others[$field] = $string;
                        }
                    }
                }
            }

            // VANISHED response (QRESYNC RFC5162)
            // Sample: * VANISHED (EARLIER) 300:310,405,411
            else if (preg_match('/^\* VANISHED [()EARLIER]*/i', $line, $match)) {
                $line   = substr($line, strlen($match[0]));
                $v_data = $this->tokenizeResponse($line, 1);

                $this->data['VANISHED'] = $v_data;
            }

        } while (!$this->startsWith($line, $key, true));

        return $result;
    }

    /**
     * Returns message(s) data (flags, headers, etc.)
     *
     * @param string $mailbox     Mailbox name
     * @param mixed  $message_set Message(s) sequence identifier(s) or UID(s)
     * @param bool   $is_uid      True if $message_set contains UIDs
     * @param bool   $bodystr     Enable to add BODYSTRUCTURE data to the result
     * @param array  $add_headers List of additional headers
     *
     * @return bool|array List of rcube_message_header elements, False on error
     */
    function fetchHeaders($mailbox, $message_set, $is_uid = false, $bodystr = false, $add_headers = array())
    {
        $query_items = array('UID', 'RFC822.SIZE', 'FLAGS', 'INTERNALDATE');
        $headers     = array('DATE', 'FROM', 'TO', 'SUBJECT', 'CONTENT-TYPE', 'CC', 'REPLY-TO',
            'LIST-POST', 'DISPOSITION-NOTIFICATION-TO', 'X-PRIORITY');

        if (!empty($add_headers)) {
            $add_headers = array_map('strtoupper', $add_headers);
            $headers     = array_unique(array_merge($headers, $add_headers));
        }

        if ($bodystr) {
            $query_items[] = 'BODYSTRUCTURE';
        }

        $query_items[] = 'BODY.PEEK[HEADER.FIELDS (' . implode(' ', $headers) . ')]';

        $result = $this->fetch($mailbox, $message_set, $is_uid, $query_items);

        return $result;
    }

    /**
     * Returns message data (flags, headers, etc.)
     *
     * @param string $mailbox     Mailbox name
     * @param int    $id          Message sequence identifier or UID
     * @param bool   $is_uid      True if $id is an UID
     * @param bool   $bodystr     Enable to add BODYSTRUCTURE data to the result
     * @param array  $add_headers List of additional headers
     *
     * @return bool|rcube_message_header Message data, False on error
     */
    function fetchHeader($mailbox, $id, $is_uid = false, $bodystr = false, $add_headers = array())
    {
        $a = $this->fetchHeaders($mailbox, $id, $is_uid, $bodystr, $add_headers);
        if (is_array($a)) {
            return array_shift($a);
        }
        return false;
    }

    /**
     * Sort messages by specified header field
     *
     * @param array  $messages Array of rcube_message_header objects
     * @param string $field    Name of the property to sort by
     * @param string $flag     Sorting order (ASC|DESC)
     *
     * @return array Sorted input array
     */
    public static function sortHeaders($messages, $field, $flag)
    {
        if (empty($field)) {
            $field = 'uid';
        }
        else {
            $field = strtolower($field);
        }

        if (empty($flag)) {
            $flag = 'ASC';
        }
        else {
            $flag = strtoupper($flag);
        }

        // Strategy: First, we'll create an "index" array.
        // Then, we'll use sort() on that array, and use that to sort the main array.

        $index  = array();
        $result = array();

        reset($messages);

        while (list($key, $headers) = each($messages)) {
            $value = null;

            switch ($field) {
            case 'arrival':
                $field = 'internaldate';
            case 'date':
            case 'internaldate':
            case 'timestamp':
                $value = self::strToTime($headers->$field);
                if (!$value && $field != 'timestamp') {
                    $value = $headers->timestamp;
                }

                break;

            default:
                // @TODO: decode header value, convert to UTF-8
                $value = $headers->$field;
                if (is_string($value)) {
                    $value = str_replace('"', '', $value);
                    if ($field == 'subject') {
                        $value = preg_replace('/^(Re:\s*|Fwd:\s*|Fw:\s*)+/i', '', $value);
                    }

                    $data = strtoupper($value);
                }
            }

            $index[$key] = $value;
        }

        if (!empty($index)) {
            // sort index
            if ($flag == 'ASC') {
                asort($index);
            }
            else {
                arsort($index);
            }

            // form new array based on index
            while (list($key, $val) = each($index)) {
                $result[$key] = $messages[$key];
            }
        }

        return $result;
    }

    function fetchMIMEHeaders($mailbox, $uid, $parts, $mime=true)
    {
        if (!$this->select($mailbox)) {
            return false;
        }

        $result = false;
        $parts  = (array) $parts;
        $key    = $this->nextTag();
        $peeks  = array();
        $type   = $mime ? 'MIME' : 'HEADER';

        // format request
        foreach ($parts as $part) {
            $peeks[] = "BODY.PEEK[$part.$type]";
        }

        $request = "$key UID FETCH $uid (" . implode(' ', $peeks) . ')';

        // send request
        if (!$this->putLine($request)) {
            $this->setError(self::ERROR_COMMAND, "Unable to send command: $request");
            return false;
        }

        do {
            $line = $this->readLine(1024);

            if (preg_match('/^\* [0-9]+ FETCH [0-9UID( ]+BODY\[([0-9\.]+)\.'.$type.'\]/', $line, $matches)) {
                $idx     = $matches[1];
                $headers = '';

                // get complete entry
                if (preg_match('/\{([0-9]+)\}\r\n$/', $line, $m)) {
                    $bytes = $m[1];
                    $out   = '';

                    while (strlen($out) < $bytes) {
                        $out = $this->readBytes($bytes);
                        if ($out === null)
                            break;
                        $headers .= $out;
                    }
                }

                $result[$idx] = trim($headers);
            }
        } while (!$this->startsWith($line, $key, true));

        return $result;
    }

    function fetchPartHeader($mailbox, $id, $is_uid=false, $part=NULL)
    {
        $part = empty($part) ? 'HEADER' : $part.'.MIME';

        return $this->handlePartBody($mailbox, $id, $is_uid, $part);
    }

    function handlePartBody($mailbox, $id, $is_uid=false, $part='', $encoding=NULL, $print=NULL, $file=NULL, $formatted=false, $max_bytes=0)
    {
        if (!$this->select($mailbox)) {
            return false;
        }

        $binary    = true;

        do {
            if (!$initiated) {
                switch ($encoding) {
                case 'base64':
                    $mode = 1;
                    break;
                case 'quoted-printable':
                    $mode = 2;
                    break;
                case 'x-uuencode':
                case 'x-uue':
                case 'uue':
                case 'uuencode':
                    $mode = 3;
                    break;
                default:
                    $mode = 0;
                }

                // Use BINARY extension when possible (and safe)
                $binary     = $binary && $mode && preg_match('/^[0-9.]+$/', $part) && $this->hasCapability('BINARY');
                $fetch_mode = $binary ? 'BINARY' : 'BODY';
                $partial    = $max_bytes ? sprintf('<0.%d>', $max_bytes) : '';

                // format request
                $key       = $this->nextTag();
                $request   = $key . ($is_uid ? ' UID' : '') . " FETCH $id ($fetch_mode.PEEK[$part]$partial)";
                $result    = false;
                $found     = false;
                $initiated = true;

VARDUMP($request);
                // send request
                if (!$this->putLine($request)) {
                    $this->setError(self::ERROR_COMMAND, "Unable to send command: $request");
                    return false;
                }

                if ($binary) {
                    // WARNING: Use $formatted argument with care, this may break binary data stream
                    $mode = -1;
                }
            }

            $line = trim($this->readLine(1024));

            if (!$line) {
                break;
            }

            // handle UNKNOWN-CTE response - RFC 3516, try again with standard BODY request
            if ($binary && !$found && preg_match('/^' . $key . ' NO \[UNKNOWN-CTE\]/i', $line)) {
                $binary = $initiated = false;
                continue;
            }

            // skip irrelevant untagged responses (we have a result already)
            if ($found || !preg_match('/^\* ([0-9]+) FETCH (.*)$/', $line, $m)) {
                continue;
            }

            $line = $m[2];

            // handle one line response
            if ($line[0] == '(' && substr($line, -1) == ')') {
                // tokenize content inside brackets
                // the content can be e.g.: (UID 9844 BODY[2.4] NIL)
                $tokens = @$this->tokenizeResponse(preg_replace('/(^\(|\)$)/', '', $line));

                for ($i=0; $i<count($tokens); $i+=2) {
                    if (preg_match('/^(BODY|BINARY)/i', $tokens[$i])) {
                        $result = $tokens[$i+1];
                        $found  = true;
                        break;
                    }
                }

                if ($result !== false) {
                    if ($mode == 1) {
                        $result = base64_decode($result);
                    }
                    else if ($mode == 2) {
                        $result = quoted_printable_decode($result);
                    }
                    else if ($mode == 3) {
                        $result = convert_uudecode($result);
                    }
                }
            }
            // response with string literal
            else if (preg_match('/\{([0-9]+)\}$/', $line, $m)) {
                $bytes = (int) $m[1];
                $prev  = '';
                $found = true;

                // empty body
                if (!$bytes) {
                    $result = '';
                }
                else while ($bytes > 0) {
                    $line = $this->readLine(8192);

                    if ($line === NULL) {
                        break;
                    }

                    $len = strlen($line);

                    if ($len > $bytes) {
                        $line = substr($line, 0, $bytes);
                        $len  = strlen($line);
                    }
                    $bytes -= $len;

                    // BASE64
                    if ($mode == 1) {
                        $line = preg_replace('|[^a-zA-Z0-9+=/]|', '', $line);
                        // create chunks with proper length for base64 decoding
                        $line = $prev.$line;
                        $length = strlen($line);
                        if ($length % 4) {
                            $length = floor($length / 4) * 4;
                            $prev = substr($line, $length);
                            $line = substr($line, 0, $length);
                        }
                        else {
                            $prev = '';
                        }
                        $line = base64_decode($line);
                    }
                    // QUOTED-PRINTABLE
                    else if ($mode == 2) {
                        $line = rtrim($line, "\t\r\0\x0B");
                        $line = quoted_printable_decode($line);
                    }
                    // UUENCODE
                    else if ($mode == 3) {
                        $line = rtrim($line, "\t\r\n\0\x0B");
                        if ($line == 'end' || preg_match('/^begin\s+[0-7]+\s+.+$/', $line)) {
                            continue;
                        }
                        $line = convert_uudecode($line);
                    }
                    // default
                    else if ($formatted) {
                        $line = rtrim($line, "\t\r\n\0\x0B") . "\n";
                    }

                    if ($file) {
                        if (fwrite($file, $line) === false) {
                            break;
                        }
                    }
                    else if ($print) {
                        echo $line;
                    }
                    else {
                        $result .= $line;
                    }
                }
            }
        } while (!$this->startsWith($line, $key, true) || !$initiated);

        if ($result !== false) {
            if ($file) {
                return fwrite($file, $result);
            }
            else if ($print) {
                echo $result;
                return true;
            }

            return $result;
        }

        return false;
    }
}


///////////////////////////////////////////////////////////////////////////
// stream interface
///////////////////////////////////////////////////////////////////////////

class ImapCustomStream {
	public $inQ;
	public $outQ;
	
	private $isOpen = false;
	private $state;

	function stream_open($path, $mode, $options, &$opened_path) {
// 		VARDUMP('open');
		$this->imap_handler('open');
		return $this->isOpen;
	}

	function stream_flush() {
// 		VARDUMP('flush');
		$this->imap_handler();
		while (strlen($this->inQ)) {
			$this->imap_handler();
		}
	}

	function stream_close() {
// 		VARDUMP('closing');
		$this->stream_flush();
		$this->imap_handler('close');
		$this->isOpen = false;
		unset($this->inQ, $this->outQ);
// 		VARDUMP('closed');
	}

	function stream_read($count) {
// 		VARDUMP('read');
// 		debugmsg('read'); // uncomment to see where we are being used from
		$this->imap_handler();
		$len = strlen($this->outQ);
		if ($len >= $count) $len = $count;
		$ret = substr($this->outQ, 0, $len);
		$this->outQ = substr($this->outQ, $len);
		$this->imap_handler();
// 		VARDUMP($ret);
		return $ret;
	}

	function stream_write($data) {
// 		VARDUMP($data);
// 		debugmsg("write", $data);
		$this->imap_handler();
		$this->inQ .= $data;
		$this->imap_handler();
		return strlen($data);
	}

	function stream_tell() {
		var_dump('tell');
		return false;
	}

	function stream_eof() {
// 		VARDUMP('eof='.intval(!$this->isOpen));
		$this->imap_handler();
		return !$this->isOpen;
	}

	function stream_seek($offset, $whence) {
		var_dump('seek');
		switch ($whence) {
			case SEEK_SET:
			case SEEK_CUR:
			case SEEK_END:
				if ($offset == 0) return true;
				return false;
				break;
			default:
				return false;
		}
	}
	
	function stream_set_option($option, $arg1, $arg2) {
		switch($option) {
		case 4: // timeout
			return true;
		default:
			var_dump($option, $arg1, $arg2);
		}
		return false;
	}
	
	function imap_handler($cmd = false) {
		if ($cmd === 'open' && empty($this->state)) {
			$this->state = new stdClass();
			$this->isOpen = true;
			$this->state->pending = array();
			$this->state->complete = array();
			$this->outQ .= "* OK IMAP4rev1 Service Ready\r\n";
		} elseif (!$this->isOpen) {
			return false;
		} elseif ($cmd) {
			switch($cmd) {
			case 'close': // terminating the connection
				break;
			default:
				throw new Exception("Unknown command: $cmd");
			}
		} elseif (!empty($this->state->callback)) {
			$this->{$this->state->callback}();
		} elseif (!empty($this->inQ)) {
ob_end_flush();
			do {
				$ret = $this->imap_input();
			} while($ret && $this->inQ > '' && strlen($this->outQ) < 8192);
		}
		if (!empty($this->state->pending)) $this->imap_handle_all_pending();
	}
	
	function imap_input() {
		$line = $this->imap_input_readline();
		if ($line === false) return false;
		$this->imap_input_parseline($line);
		return true;
	}
	
	function imap_input_readline() {
		$pos = strpos($this->inQ, "\r\n");
		if ($pos === false) return false;
		$line = substr($this->inQ, 0, $pos);
		$this->inQ = substr($this->inQ, $pos+2);
// 		VARDUMP("inQ Update:");
		VARDUMP($line);
// 		VARDUMP($this->inQ);
// 		VARDUMP(bin2hex($this->inQ));
		return $line;
	}
	
	function imap_input_parseline($line) {
		if (!preg_match('/^([A-Za-z0-9*]+) (.*)$/', $line, $m)) {
			throw new Exception("Unable to parse line: $line");
		}
		$tag = trim($m[1]);
		$obj = (object)array(
			'tag' => $tag,
			'cmd' => $m[2],
		);
		$this->state->pending[$tag] = $obj;
	}
	
	function imap_handle_all_pending() {
ob_end_flush();
		$outQsize = strlen($this->outQ);
		foreach($this->state->pending as $tag => $obj) {
			$this->imap_handle_pending($obj);
		}
		foreach($this->state->complete as $tag => $obj) {
			if (isset($this->state->pending[$tag])) {
				unset($this->state->pending[$tag]);
			}
		}
		$this->state->complete = array();
		$out = substr($this->outQ, $outQsize);
		if (!empty($out)) {
// 			VARDUMP($out);
		}
	}
	
	function imap_raw($msg) {
		$this->outQ .= "$msg\r\n";
	}
	
	function imap_untagged($type, $msg) {
		$this->outQ .= "* $type $msg\r\n";
	}
	
	function imap_complete($o, $state, $msg = '') {
		$line = "{$o->tag} ";
		switch($state) {
		case 'OK':  $line .= "OK";  break;
		case 'NO':  $line .= "NO";  break;
		default:
		case 'BAD': $line .= "BAD"; break;
		}
		if (!empty($msg)) {
			$line .= " $msg";
		}
		$this->outQ .= $line."\r\n";
		$this->state->complete[$o->tag] = $o;
// 		debugmsg('complete outQ', $this->outQ);
	}
	
	function imap_handle_pending($o) {
		if (empty($o->handler)) {
			if (!preg_match('~^([^ ]+)( (.*))?$~', $o->cmd, $m)) {
				$this->imap_complete($o, 'BAD', "unable to parse message");
				return;
			}
			$o->handler = array($this, 'imap_handle_cmd');
			$o->args = $m[3];
			$o->cmd = strtoupper($m[1]);
		}
		call_user_func_array($o->handler, array(&$o));
		return;
	}
	
	function imap_handle_cmd($o) {
		switch($o->cmd) {
		case 'CAPABILITY':
			$this->imap_untagged($o->cmd, "IMAP4rev1 AUTH=XPLAIN");
			$this->imap_complete($o, 'OK', "CAPABILITY completed");
			break;
		case 'LOGOUT':
			$this->imap_untagged('BYE', "IMAP4rev1 Server logging out");
			$this->imap_complete($o, 'OK', "LOGOUT completed");
			break;
		case 'LOGIN': $this->imap_handle_login($o); break;
// 		case 'AUTHENTICATE': $this->imap_handle_auth($o); break;
		case 'LIST':  $this->imap_handle_list($o); break;
		case 'STATUS':  $this->imap_handle_status($o); break;
		case 'SELECT':  $this->imap_handle_select($o); break;
		case 'SEARCH':  $this->imap_handle_search($o); break;
		case 'FETCH':   $this->imap_handle_fetch($o); break;
		case 'UID':     $this->imap_handle_uid($o); break;
		case 'UID SEARCH':  $this->imap_handle_search($o); break;
		case 'UID FETCH':   $this->imap_handle_fetch($o); break;
		case 'LSUB':
			$this->imap_complete($o, 'OK', "LSUB completed");
			break;
		case 'NOOP':
		default:
			var_dump("Unknown cmd: {$o->cmd}");
			var_dump($this->state);
			flush();
			$this->imap_complete($o, 'BAD', "Unknown cmd: {$o->cmd}");
		}
		return;
	}

	function imap_handle_login($o) {
		$args = explode(' ', $o->args);
		if (!is_array($args) || count($args) != 2) {
			$this->imap_complete($o, 'BAD', "invalid credentials");
			return;
		}
		if ($args[0] !== $args[1] || preg_match('~/|\.\.|[^!-z]~', $args[0])) {
			$this->imap_complete($o, 'NO', "invalid credentials");
			return;
		}
		$o->args = $args;
		$this->state->user = $args[0];
		$this->imap_complete($o, 'OK', "LOGIN completed");
		return;
	}

// 	function imap_handle_auth($o) {
// 		if ($o->args !== 'PLAIN') {
// 			$this->imap_complete($o, 'NO', "invalid method");
// 			return;
// 		}
// 		$this->state->authMethod = $o->args;
// 		$o->handler = array($this, 'imap_handle_auth_phase2');
// 		$this->state->o = $o;
// 		$this->state->callback = 'imap_callback_auth';
// 		$this->imap_raw("+");
// 		return;
// 	}
// 	
// 	function imap_callback_auth() {
// 		$line = $this->imap_input_readline();
// 		if ($line === false) {
// // 			$o->result = 'failure to read input line';
// // 			$this->state->callback = NULL;
// 			return;
// 		}
// 		$o = $this->state->o;
// 		$dec = base64_decode($line);
// var_dump("Dec input line: $dec");
// 		if ($dec === false) {
// 			$o->response = array('NO', "invalid PLAIN base64 response");
// 		} elseif (!preg_match('/^\0([^\0]*)\0([^\0]*)$/', $dec, $m)) {
// 			$o->response = array('NO', "invalid AUTHENTICATE");
// 		} elseif (empty($m[1]) || empty($m[2])
// 			|| $m[1] !== $m[2]
// 			|| preg_match('~/|\.\.|[^!-z]~', $m[1])
// 			) {
// 			$o->response = array('NO', "invalid credentials");
// 		} else {
// 			$o->user = $m[1];
// 			$o->response = array('OK', "AUTHENTICATE completed");
// 		}
// VARDUMP($o->response);
// 		$this->state->o = NULL;
// 		$this->state->callback = NULL;
// 	}
// 
// 	function imap_handle_auth_phase2($o) {
// VARDUMP($o->response);
// 		$this->state->user = $o->user;
// 		$this->imap_complete($o, $o->response[0], $o->response[1]);
// 	}
	
	function imap_handle_list($o) {
		$args = explode(' ', $o->args);
		if (!is_array($args) || count($args) != 2) {
			$this->imap_complete($o, 'BAD', "invalid LIST");
			return;
		}
		$ref = $args[0];
		$mbox = $args[1];
		// empty reference means default
		if ($ref === '""') $ref = '';
		// empty mailbox name means "return the hierarchy delimiter and the root name of the name given in the reference"
		if ($mbox === '""') {
			$mbox = 'NIL';
			$this->imap_untagged($o->cmd, '(\Noselect) "/" ""');
			$this->imap_untagged($o->cmd, '(\Noinferiors) "" "INBOX"');
			$this->imap_complete($o, 'OK', "LIST completed");
			return;
		}
// 		if ($args[0] !== $args[1]) {
// 			$this->imap_complete($o, 'NO', "invalid credentials");
// 			return;
// 		}
		$this->imap_complete($o, 'OK', "LIST completed");
		return;
	}
	
	function imap_parse_sequence_set($ss, $lastindex) {
		$a = array();
		$setlist = explode(',', $ss);
		if (!is_array($setlist)) return false;
		foreach($setlist as $range) {
			$range = explode(':', $range);
			$rangeCount = count($range);
			switch($rangeCount) {
			case 1:
				$t = ($range[0] == '*') ? $lastindex : intval($range[0]);
				if (!isset($a[$t])) $a[$t] = $t;
				break;
			case 2:
				$start = ($range[0] == '*') ? $lastindex : intval($range[0]);
				$end = ($range[1] == '*') ? $lastindex : intval($range[1]);
				if ($start > $end) {
					$t = $start;
					$start = $end;
					$end = $t;
				}
				$t = range($start, $end);
				$a += array_flip($t);
				break;
			default:
var_dump("invalid sequence-set: rangeCount=$rangeCount; setlist=$setlist");
				return false;
			}
		}
		$a = array_keys($a);
		$a = array_combine($a, $a);
		return $a;
	}

	function getMbox($user) {
// 		$tfn='/tmp/mbox.'.$user;
		if (isset($this->mbox) && ($user == $this->state->user)) {
			$mbox = $this->mbox;
// 		} elseif (file_exists($tfn)) {
// 			$mbox = unserialize(file_get_contents($tfn));
// 			$this->mbox = $mbox;
		} else {
			$mbox = new SpoolMailboxWrapper($user);
// 			file_put_contents($tfn, serialize($mbox));
		}
		return $mbox;
	}
	
	function imap_handle_status($o) {
		if (!preg_match('~^([^ ]+)( \((.*)\))?$~', $o->args, $m)) {
			$this->imap_complete($o, 'BAD', "unable to parse arguments");
			return;
		}
		if ($m[1] !== 'INBOX') {
			$this->imap_complete($o, 'NO', "invalid mailbox");
			return;
		}
		$items = explode(' ', strtoupper($m[3]));
		if (empty($items)) {
			$this->imap_complete($o, 'NO', "no data items");
			return;
		}
		$mbox = $this->getMbox($this->state->user);
		$line = 'INBOX (';
		foreach($items as $item) {
			$line .= $item;
			switch($item) {
				case 'MESSAGES':
				case 'RECENT':
				case 'UNSEEN':
					$cnt = $mbox->getMessageCount();
					$line .= " $cnt ";
					break;
				default:
					$line .= " UNKNOWN ";
					break;
			}
		}
		$line = rtrim($line) . ')';
		$this->imap_untagged($o->cmd, $line);
		$this->imap_complete($o, 'OK', "STATUS completed");
	}
	
	function imap_handle_select($o) {
		if (!preg_match('~^([^ ]+)$~', $o->args, $m)) {
			$this->imap_complete($o, 'BAD', "unable to parse arguments");
			return;
		}
		if ($m[1] !== 'INBOX') {
			$this->imap_complete($o, 'NO', "no such mailbox");
			return;
		}
		$mboxname = $m[1];
		$mbox = $this->getMbox($this->state->user);
		$this->mbox = $mbox;
		$cnt = $mbox->getMessageCount();
		$uidvalidity = $mbox->getUidValidity();
		$nextuid = $cnt+1;
		// REQUIRED untagged: FLAGS, EXISTS, RECENT
		$this->imap_untagged("FLAGS", '()');
		$this->imap_untagged("$cnt", 'EXISTS');
		$this->imap_untagged("$cnt", 'RECENT');
		// REQUIRED OK untagged: UNSEEN, PERMANENTFLAGS, UIDNEXT, UIDVALIDITY
		$this->imap_untagged("OK", "[UNSEEN 1] Message 1 is first unseen");
		$this->imap_untagged("OK", "[PERMANENTFLAGS ()] No permanent flags permitted");
		$this->imap_untagged("OK", "[UIDNEXT $nextuid] Predicted next UID");
		$this->imap_untagged("OK", "[UIDVALIDITY $uidvalidity] UIDs valid");
		$this->imap_complete($o, 'OK', "[READ-ONLY] SELECT completed");
	}
	
	function imap_handle_search($o) {
		if (!preg_match('~^([0-9]+|ALL)$~', $o->args, $m)) {
			$this->imap_complete($o, 'NO', "cannot search that criteria");
			return;
		}
		$mbox = $this->getMbox($this->state->user);
		$this->mbox = $mbox;
		$cnt = $mbox->getMessageCount();
		if ($m[1] == 'ALL') {
			$line = '';
			for($i=1; $i<=$cnt; $i++) {
				$line .= " $i";
			}
			$line = ltrim($line);
		} else {
			$i = intval($m[1]);
			if ($i <= 0) {
				$this->imap_complete($o, 'NO', "cannot search that criteria");
				return;
			}
			if ($i <= $cnt) {
				$line = $i;
			}
		}
		if ($o->subcmd) {
			$this->imap_untagged($o->subcmd, $line);
			$this->imap_complete($o, 'OK', "UID SEARCH completed");
		} else {
			$this->imap_untagged($o->cmd, $line);
			$this->imap_complete($o, 'OK', "SEARCH completed");
		}
	}
	
	function imap_handle_uid($o) {
		if (!isset($o->subcmd)) {
			if (!preg_match('~^(SEARCH|FETCH)( (.*))?$~', $o->args, $m)) {
VARDUMP($o);
				$this->imap_complete($o, 'BAD', "unable to parse arguments");
				return;
			}
			$o->subcmd=strtoupper($m[1]);
			$o->args = $m[3];
		}
		$o->cmd = "{$o->cmd} {$o->subcmd}";
		switch($o->subcmd) {
		case 'SEARCH': $this->imap_handle_search($o); break;
		case 'FETCH': $this->imap_handle_fetch($o); break;
		default:
VARDUMP($o);
			$this->imap_complete($o, 'BAD', "unable to parse arguments");
		}
	}
	
	function imap_handle_fetch($o) {
		if (!preg_match('~^([0-9:,*]+) (.*)$~', $o->args, $m)) {
			$this->imap_complete($o, 'BAD', "cannot fetch data, parse failure");
			return;
		}
		$o->fields = $this->imap_handle_fetch_fields($m[2]);
VARDUMP($o->fields);
// echo '<pre>';
// var_export($o->fields);
// echo '</pre>';
		$mbox = $this->getMbox($this->state->user);
		$this->mbox = $mbox;
		$cnt = $mbox->getMessageCount();
		// parse sequence-set list
		$list = $this->imap_parse_sequence_set($m[1], $cnt);
		if ($msgs === false) {
			$this->imap_complete($o, 'BAD', "cannot fetch data, parse failure");
			return;
		}
		$requestedItems = count($list);
		// reparse list into ranges where possible
		$ranges = array();
		$start = $end = array_shift($list);
		foreach($list as $next) {
			if ($next == $end+1) {
				$end = $next;
			} else {
				$ranges[] = array($start, $end);
				$start = $end = $next;
			}
		}
		$ranges[] = array($start, $end);
		unset($list);
		// get messages from ranges and generate untagged responses
		$foundItems = 0;
		foreach($ranges as $range) {
			$start = $range[0] - 1;
			if ($range[0] !== $range[1]) {
				$end = $range[1] - 1;
				$msgs = $mbox->getMsgs($start, $end);
				if ($msgs === false) continue;
				foreach($msgs as $idx => $msg) {
					$this->imap_handle_fetch_parsemsg($o, $idx + 1, $msg);
					$foundItems++;
				}
			} else {
				$msg = $mbox->getMsg($start);
				if ($msg === false) continue;
				$this->imap_handle_fetch_parsemsg($o, $start + 1, $msg);
				$foundItems++;
			}
		}
		if ($foundItems == 0) {
			$this->imap_complete($o, 'NO', "could not fetch data");
			return;
		}
		if ($o->subcmd) {
			$this->imap_complete($o, 'OK', "UID FETCH completed");
		} else {
			$this->imap_complete($o, 'OK', "FETCH completed");
		}
	}
	
	function imap_handle_fetch_fields($fields) {
		$o = array('children' => array());
		$fields = str_replace('[', '[ ', $fields);
		$fields = preg_replace('~(\]|[()<>])~', ' $1 ', $fields);
		$fields = trim($fields);
		while (strpos($fields, '  ') !== false) {
			$fields = str_replace('  ', ' ', $fields);
		}
		$fields = explode(' ', $fields);
		foreach($fields as $fi => $field) {
			switch($field) {
			// normal fields
			case 'FLAGS':
			case 'UID':
			case 'RFC822.SIZE':
			case 'INTERNALDATE':
			case 'BODYSTRUCTURE':
			// body fields
			case 'HEADER':
			case 'HEADER.FIELDS':
			// headers
			case 'DATE':
			case 'FROM':
			case 'TO':
			case 'SUBJECT':
			case 'CONTENT-TYPE':
			case 'CC':
			case 'REPLY-TO':
			case 'LIST-POST':
			case 'DISPOSITION-NOTIFICATION-TO':
			case 'X-PRIORITY':
			case 'IN-REPLY-TO':
			case 'BCC':
			case 'SENDER':
			case 'MESSAGE-ID':
			case 'CONTENT-TRANSFER-ENCODING':
			case 'REFERENCES':
			case 'X-DRAFT-INFO':
			case 'MAIL-FOLLOWUP-TO':
			case 'MAIL-REPLY-TO':
			case 'RETURN-PATH':
				 $o['children'][] = $field;
				 break;
			// open/close blocks
			case 'BODY[':
			case 'BODY.PEEK[':
			case '(':
			case '[':
			case '<':
				$o = array(
					'starttag' => $field,
					'parents' => $o,
					'children' => array(),
				);
				break;
			case ')':
			case ']':
			case '>':
				$p = $o['parents'];
				unset($o['parents']);
				$t = (object)$o;
				if (isset($p['children'])) {
					$p['children'][] = $t;
				} else {
					$p[] = $t;
				}
				$o = $p;
				break;
			// incomplete structures
			case 'BODY':
			default:
				if (preg_match('~^[0-9]+$~', $field) && preg_match('~^BODY(.PEEK)?\[$~i', $o['starttag'])) {
					$o['children'][] = $field;
				} elseif (preg_match('~^[0-9]+$~', $field)) {
					var_dump("Unknown numeric FETCH field: $field");
				} else {
					var_dump("Unknown FETCH field: $field");
				}
			}
		}
		$o = (object)$o;
		return $o;
	}
	
	static function escape($s) {
		return rcube_imap_generic::escape($s, true);
	}
	
	function getBodyStructureText($msg, $mail, $part) {
		static $r_implode = array('rcube_imap_generic', 'r_implode');
		static $escape = array(__CLASS__, 'escape');
		// ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 2279 48)
		$mimeinfo = mailparse_msg_get_part_data(mailparse_msg_get_part($mail, $part));
		$type = explode('/', $mimeinfo['content-type']);
		$len = $mimeinfo['ending-pos'] - $mimeinfo['starting-pos'];
		switch(strtolower($type[0])) {
		case 'text':
			
			break;
		default:
var_dump("unknown type: $type[0]/$type[1]");
		}
		$a = $r_implode(array(
			$escape($type[0]),
			$escape($type[1]),
			$r_implode(array(
				$escape('CHARSET'),
				$escape($mimeinfo['charset']),
			)),
			$escape($mimeinfo['headers']['message-id']),
			$escape(NULL), // Body Description
			$escape($mimeinfo['transfer-encoding']),
			$escape($len),
			$escape($mimeinfo['line-count']),
		));
		/* Optional extension data fields:
		body MD5
		body disposition
		body language
		body location
		*/
		return $a;
	}
	
	function getBodyStructureMulti($msg, $mail, $parts) {
		static $r_implode = array('rcube_imap_generic', 'r_implode');
		static $escape = array(__CLASS__, 'escape');
		// (("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 1152          23)("TEXT" "PLAIN" ("CHARSET" "US-ASCII" "NAME" "cc.diff")          "<960723163407.20117h@cac.washington.edu>" "Compiler diff" "BASE64" 4554 73) "MIXED")
		$structure = '(';
		$structureEnd=')';
		foreach($parts as $pi => $part) {
			if ($pi == 0) continue;
			if (is_array($part)) {
				$children = $this->getBodyStructureMulti($msg, $mail, $part);
				if (!empty($children)
				&& ($children[0] == '(')
				&& (substr($children, -1) == ')')
				&& (strpos($children, ')(') !== false)
				) {
					$children = substr($children, 1, -1);
				}
				$structure .= $children;
				$part = $part[0];
				$mimeinfo = mailparse_msg_get_part_data(mailparse_msg_get_part($mail, $part));
				$type = explode('/', $mimeinfo['content-type']);
				$len = $mimeinfo['ending-pos'] - $mimeinfo['starting-pos'];
				$structure .= ' '.join(' ', array(
					$escape($type[1]),
					$r_implode(array(
						$escape('CHARSET'),
						$escape($mimeinfo['charset']),
					)),
// 					$escape(NULL), // Body Disposition
					));
			} else {
				$structure .= $this->getBodyStructureText($msg, $mail, $part);
			}
		}
		$structure .= $structureEnd;
		return $structure;
	}
	
	function getBodyStructureParts($parts, $prefix='') {
		$ret = array();
		foreach($parts as $part) {
			// verify we have a matching prefix
			$iterPfx = substr($part, 0, strlen($prefix));
			if ($iterPfx !== $prefix) continue;
			// get the unique part
			$iterPart = substr($part, strlen($prefix));
			$t = explode('.', $iterPart, 2);
			$k = array_shift($t);
			if (!isset($ret[$k])) {
				$ret[$k] = $part;
			} else {
				$t = $this->getBodyStructureParts($parts, "{$prefix}{$k}.");
				if (!is_array($ret[$k])) {
					$ret[$k] = array(0 => $ret[$k]) + $t;
				} else {
					$ret[$k] += $t;
				}
			}
		}
		return $ret;
	}
	
	function getBodyStructure($msg, $mail) {
		$parts = mailparse_msg_get_structure($mail);
		$multipart = count($parts) > 1;
		if (!$multipart) {
			$structure = $this->getBodyStructureText($msg, $mail, $parts[0]);
		} else {
			$parts = $this->getBodyStructureParts($parts);
			$structure = $this->getBodyStructureMulti($msg, $mail, $parts);
		}
		return $structure;
	}
	
	function imap_handle_fetch_parsemsg($o, $idx, $msg) {
		//TODO: useful builtins:
		// imap_rfc822_parse_headers()
		// imap_mime_header_decode()
		
		// parse email message - mailparse_*() require PECL module
		$mail = mailparse_msg_create();
		if (!mailparse_msg_parse($mail, $msg)) {
			var_dump("failed to parse message $idx");
			return false;
		}
		$info = mailparse_msg_get_part_data($mail);
// 		var_dump($info);
		
		// build response line with requested fields
		$line = "{$o->subcmd} ";
		$headers = '';
		$stack = array();
		$f = $o->fields;
		$waitfor = NULL;
		do {
			if (!empty($stack)) {
				list($f, $waitfor, $prevline) = array_pop($stack);
			} else {
				$waitfor = NULL;
			}
			$doBreak = false;
			foreach($f->children as $fi => $field) {
				if (!is_null($waitfor)) {
					// skip everything before $waitfor
					if ($fi !== $waitfor) continue;
					// clear $waitfor
					$waitfor = NULL;
					// process anything necessary for closing tags
					switch(substr($field->starttag, -1)) {
					case '(': $closer=')'; break;
					case '[': $closer=']'; break;
					case '<': $closer='>'; break;
					default:
						var_dump("unknown starttag: {$field->starttag}");
					}
					if (substr($line, -1) === ' ') {
						$line = substr($line, 0, -1);
					}
					$line .= "$closer";
					// append header data if necessary
					if (substr($field->starttag, 0, 4) == 'BODY') {
						if ($headers == '') {
							$len = $info['ending-pos-body'] - $info['starting-pos-body'];
							$headers .= substr($msg, $info['starting-pos-body'], $len);
						}
						$line .= ' '.getImapStr($headers).' ';
						$headers = '';
					}
					// skip past $fi since we already processed it
					continue;
				}
				if (is_object($field)) {
					array_push($stack, array($f, $fi));
					array_push($stack, array($field, NULL));
					$field = $field->starttag;
					$doBreak = true;
				}
				switch($field) {
				// normal fields
				case 'FLAGS':        $line .= "$field (\Recent) "; break;
				case 'UID':          $line .= "$field $idx "; break;
				case 'RFC822.SIZE':  $line .= "$field ".strlen($msg)." "; break;
				case 'INTERNALDATE':
					$line .= "$field ".getImapStr($info['headers']['date']).' ';
					break;
				case 'BODYSTRUCTURE':
					$structure = $this->getBodyStructure($msg, $mail);
					$line .= "$field $structure ";
					break;
				// body fields
				case 'HEADER':
					$line .= "$field ";
					$len = $info['starting-pos-body'] - $info['starting-pos'];
					$headers .= substr($msg, $info['starting-pos'], $len);
					break;
				case 'HEADER.FIELDS':
					$line .= "$field ";
					break;
				// headers
				case 'DATE':
				case 'FROM':
				case 'TO':
				case 'SUBJECT':
				case 'CONTENT-TYPE':
				case 'REPLY-TO':
				// these following are not in our test content
				case 'CC':
				case 'LIST-POST':
				case 'DISPOSITION-NOTIFICATION-TO':
				case 'X-PRIORITY':
				// these were requested on message select
				case 'IN-REPLY-TO':
				case 'BCC':
				case 'SENDER':
				case 'MESSAGE-ID':
				case 'CONTENT-TRANSFER-ENCODING':
				case 'REFERENCES':
				case 'X-DRAFT-INFO':
				case 'MAIL-FOLLOWUP-TO':
				case 'MAIL-REPLY-TO':
				case 'RETURN-PATH':
					$t = strtolower($field);
					if (!empty($info['headers'][$t])) {
						$headers .= "$field: ".($info['headers'][$t])."\r\n";
					}
					break;
				// open/close blocks
				case 'BODY.PEEK[':
					$line .= "BODY[";
					break;
				case 'BODY[':
				case '(':
				case '[':
				case '<':
					$line .= $field;
					break;
				case ')':
				case ']':
				case '>':
					$line .= "$field ";
					break;
				// incomplete structures
				case 'BODY':
				case 'BODYSTRUCTURE':
				default:
					if (preg_match('~^[0-9]+$~', $field) && preg_match('~^BODY(.PEEK)?\[$~i', $f->starttag)) {
						$parts = mailparse_msg_get_structure($mail);
if (!isset($parts[$field])) {
	VARDUMP($field);
	VARDUMP($parts[$field]);
} else {
						$field = $parts[$field];
}
						
						$t = mailparse_msg_get_part($mail, $field);
if (!is_resource($t)) {
	var_dump($field);
	var_dump($t);
}
						$info = mailparse_msg_get_part_data($t);
					} elseif (preg_match('~^[0-9]+$~', $field)) {
						var_dump("Unknown numeric FETCH field: $field");
					} else {
						var_dump("Unknown FETCH field: $field");
					}
				}
				if ($doBreak == true) break;
			}
		} while (!empty($stack));
		mailparse_msg_free($mail);
VARDUMP($line);
// echo '<pre>';
// var_export($line);
// echo '</pre>';
		$this->imap_untagged($idx, $line);
	}

}

class SpoolMailboxWrapper {
	protected $user;
	protected $fn;
	protected $mtime = -1;
	protected $size = -1;
	protected $f = false;
	protected $index = false;
	
	public function __construct($user) {
		$this->user = $user;
		$this->fn="/var/spool/mail/$user";
		$this->refresh();
	}
	
	public function __destruct() {
		$this->close();
	}
	
	function close() {
		if ($this->f) {
			fclose($this->f);
			$this->f = null;
		}
	}
	
	public function refresh() {
		$this->close();
		$this->mtime = filemtime($this->fn);
		$this->size = filesize($this->fn);
		$this->f=fopen($this->fn, 'r');
		$this->generateIndex();
		$this->checkForChanges();
	}
	
	public function is_changed() {
		$mtime = filemtime($this->fn);
		$size = filesize($this->fn);
		if ($this->mtime !== $mtime) return true;
		if ($this->size !== $size) return true;
		return false;
	}
	
	public function checkForChanges() {
		if ($this->is_changed()) $this->refresh();
	}
	
	function readLineFromStream() {
		$this->lineOffset = ftell($this->f);
		$line = fgets($this->f, 8192);
		if ($line !== false) {
			if (substr($line, -2) == "\r\n") {
				$line = substr($line, 0, -2);
			} elseif (substr($line, -1) == "\n") {
				$line = substr($line, 0, -1);
			} else {
var_dump('as-is ='.$line);
var_dump('as-isH='.bin2hex($line));
			}
		}
		return $line;
	}
	
	function readMsgFromStream($line) {
		$m = new stdClass();
		$headers = array();
ob_end_flush();
		while ($line !== false && $line !== '') {
			$headers[] = $line;
			
			$line = $this->readLineFromStream();
		}
		$body = '';
		$line = $this->readLineFromStream();
		while ($line !== false && !preg_match('/^From /', $line)) {
			$body .= $line."\n";
			$line = $this->readLineFromStream();
		}
		return array($line, $headers, $body);
	}
	
	function readRawEmailFromIndex($id) {
		$end = $id + 1;
		$end = ($end < count($this->index))
			? $this->index[$id+1]->offset
			: $end = $this->size;
		$start = $this->index[$id]->offset;
		$len = $end - $start;
		fseek($this->f, $start);
		$msg = fread($this->f, $len);
		if ($msg === false) return false;
		if (strlen($msg) < $len) {
			var_dump("Expected $len bytes, only got ".strlen($msg));
		}
		return $msg;
	}
	
	function generateIndex() {
		$idx = 0;
		fseek($this->f, 0);
		$line = $this->readLineFromStream();
		while(!feof($this->f)) {
			$m = new stdClass();
			$m->offset = $this->lineOffset;
			list($line, $headers, $body) = $this->readMsgFromStream($line);
// 			$m->headers = $headers;
// 			$m->body = $body;
			$this->index[$idx] = $m;
			$idx++;
			unset($headers, $body);
		}
	}
	
	function getUser() {
		return $this->user;
	}
	
	function getMessageCount() {
		$this->checkForChanges();
		return count($this->index);
	}
	
	function getUidValidity() {
		$this->checkForChanges();
		return $this->mtime;
	}
	
	function getMsg($id) {
		if ($id < 0 || $id >= count($this->index)) return false;
		return $this->readRawEmailFromIndex($id);
	}
	
	function getMsgs($start, $end) {
		if ($start > $end) {
			$t = $end;
			$end = $start;
			$start = $t;
			unset($t);
		}
		if ($start < 0 || $end >= count($this->index)) return false;
		$msgs = array();
		for($i=$start; $i <= $end; $i++) {
			$msg = $this->readRawEmailFromIndex($i);
			$msgs[$i] = $msg;
		}
		return $msgs;
	}
}
