<?php
    ///////////////////////////////////////////////////////////////////////////
    // Configuration parameters

    // Choose how much debugging info to output.
    // 0 is no output other than errors.
    // 1 is just the most useful info.
    // 10 is all info.
    $debugLevel = 1;

    // Point $twcScriptDir to the directory containing the TWCManager.py script.
    // Interprocess Communication with TWCManager.py will not work if this
    // parameter is incorrect.
    $twcScriptDir = "/home/pi/TWCManager-dracoventions";

    // End configuration parameters
    ///////////////////////////////////////////////////////////////////////////


    // Prevent page from showing cached version
    header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
    header('Last-Modified: ' . gmdate("D, d M Y H:i:s") . 'GMT');
    header('Cache-Control: no-cache, must-revalidate');
    header('Pragma: no-cache');
?><!DOCTYPE html>
<html>
<head>
    <title>TWCManager</title>
    <link rel="icon" type="image/png" href="favicon.png">
    <meta name="robots" content="noindex">
    <?php /* This tag makes the page fill a mobile phone screen. */ ?>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
<?php
    // Initialize Interprocess Communication message queue for sending commands to
    // TWCManager.py script and getting data back.  See notes in TWCManager.py for
    // how IPC works.
    $ipcKey = ftok($twcScriptDir, "T");
    echo("<script>console.log('IPC key: " . $ipcKey . "');</script>");
    $ipcQueue = msg_get_queue($ipcKey, 0666);

    if(@$_REQUEST['debugTWC'] != '') {
        print '<script>document.title = "TWCDebug";</script>';
        if(@$_REQUEST['submit'] != '') {
            if(@$_REQUEST['setDebugLevel'] > 0) {
                print '<script>document.title = "TWCDebugLevel";</script>';
                ipcCommand('setDebugLevel=' . intval($_REQUEST['setDebugLevel']));
            }
            else if(array_key_exists('beginTest', $_REQUEST)) {
                print '<script>document.title = "TWCTest";</script>';
                if($_REQUEST['beginTest'] == '') {
                    ipcCommand('beginTest');
                }
                else {
                    ipcCommand('beginTest=' . $_REQUEST['beginTest']);
                }
            }
        }
        ?>
        <form action="index.php" method="get">
            <input type="hidden" name="debugTWC" value="<?=htmlspecialchars($_REQUEST['debugTWC'])?>">
            Debug level: <input type="text" name="setDebugLevel" size="2" value="<?=htmlspecialchars(@$_REQUEST['setDebugLevel'])?>">
            <input type="submit" name="submit" value="Set">
        </form>
        <p>
        <form action="index.php" method="get">
            <input type="hidden" name="debugTWC" value="<?=htmlspecialchars($_REQUEST['debugTWC'])?>">
            Test: <input type="text" name="beginTest" size="2" value="<?=htmlspecialchars(@$_REQUEST['beginTest'])?>">
            <input type="submit" name="submit" value="Begin">
        </form>
        <p>
            <a href="index.php?sendTWCMsg=&submit=1">Send message</a>
            | <a href="index.php?setMasterHeartbeatData=&submit=1">Override master heartbeat data</a>
            | <a href="index.php?dumpState=1&submit=1">Dump state</a>
        </p><p>
        <a href="index.php?debugTWC=<?=htmlspecialchars($_REQUEST['debugTWC'])?>&beginTest=&submit=1">Begin test</a>
        </p>
        <?php
        print '</body></html>';

        exit;
    }
    elseif(@$_REQUEST['submit'] != '') {

        if(@$_REQUEST['nonScheduledAmpsMax'] != '') {
            // Someone submitted the form asking to change the power limit, so
            // tell TWCManager.py script how many amps to limit charging to.
            // A limit of -1 means track green energy sources.
            ipcCommand('setNonScheduledAmps=' . $_REQUEST['nonScheduledAmpsMax']);
        }

        if(@$_REQUEST['approveVIN'] != '') {
            ipcCommand('approveVIN=' . $_REQUEST['approveVIN'] . ',' . intval(@$_REQUEST['hours']));
        }

        if(@$_REQUEST['revokeVIN'] != '') {
            ipcCommand('revokeVIN=' . $_REQUEST['revokeVIN']);
        }

        // Give TWCManager a moment to process the command before we query state
        if(@$_REQUEST['approveVIN'] != '' || @$_REQUEST['revokeVIN'] != '') {
            usleep(500000);
        }

        if(preg_match('/^24-hour-charge/', $_REQUEST['submit'])) {
            ipcCommand('chargeNow');
        }
        else if($_REQUEST['submit'] == 'Cancel 24-hour-charge') {
            ipcCommand('chargeNowCancel');
        }
    }
?>
<form action="index.php" name="refresh" method="get">
    <table border="0" padding="0" margin="0"><tr>
        <td valign="top">
            <?php
                // TWC models in different world regions have different max amp values.
                // Default to 80 amps and expect to fix this value later based on what
                // slave TWCs connect to TWCManager.py.
                $twcModelMaxAmps = 80;

                // Get status info from TWCManager.py which includes state of each slave
                // TWC and how many amps total are being split amongst them.
                $response = ipcQuery('getStatus');
                if($debugLevel >= 1) {
                    print("Got response: '$response'<p>");
                }

                if($response != '') {
                    $status = explode('`', $response);
                    $statusIdx = 0;
                    $maxAmpsToDivideAmongSlaves = $status[$statusIdx++];
                    $wiringMaxAmpsAllTWCs = $status[$statusIdx++];
                    $minAmpsPerTWC = $status[$statusIdx++];
                    $chargeNowAmps = $status[$statusIdx++];
                    $GLOBALS['nonScheduledAmpsMax'] = $status[$statusIdx++];

                    print "<p style=\"margin-top:0;\"><strong>Power available for all TWCs:</strong> ";
                    if($maxAmpsToDivideAmongSlaves > 0) {
                          print $maxAmpsToDivideAmongSlaves . "A";
                    }
                    else {
                        print "None";
                    }

                    if($status[$statusIdx] < 1) {
                        print "</p><p style=\"margin-bottom:0\">";
                        print "<strong>No slave TWCs found on RS485 network.</strong>";
                    }
                    else {
                        // Display info about each TWC being managed.
                        $numTWCs = $status[$statusIdx++];
                        for($i = 0; $i < $numTWCs; $i++) {
                            print "</p><p style=\"margin-bottom:0\">";
                            $subStatus = explode('~', $status[$statusIdx++]);
                            $twcModelMaxAmps = $subStatus[1];
                            print("<strong>TWC " . $subStatus[0] . ':</strong> ');
                            if(count($subStatus) > 5 && $subStatus[5] != '') {
                                print '<span style="color:#666">(' . htmlspecialchars($subStatus[5]) . ')</span> ';
                            }
                            if($subStatus[2] < 1.0) {
                                /*if($subStatus[4] == 0) {
                                    // I was hoping state 0 meant no car is plugged in, but
                                    // there are periods when we're telling the car no power is
                                    // available and the state flips between 5 and 0 every
                                    // second. Sometimes it changes to state 0 for long periods
                                    // (likely when the car goes to sleep for ~15 mins at a
                                    // time) even when the car is plugged in, so it looks like
                                    // we can't actually determine if a car is plugged in or
                                    // not.
                                    print "No car plugged in.";
                                }
                                else {*/
                                if($subStatus[3] < 5.0) {
                                    if($maxAmpsToDivideAmongSlaves > 0 &&
                                       $maxAmpsToDivideAmongSlaves < $minAmpsPerTWC) {
                                        print "Power available less than {$minAmpsPerTWC}A (minAmpsPerTWC).";
                                    }
                                    else {
                                        print "No power available.";
                                    }
                                }
                                else {
                                    print "Finished charging, unplugged, or waking up."
                                        . " (" . $subStatus[3] . "A available)";
                                }
                            }
                            else {
                                print "Charging at " . $subStatus[2] . "A";
                                if($subStatus[3] - $subStatus[2] > 1.0) {
                                    // Car is using over 1A less than is available, so print
                                    // a note.
                                    print " (" . $subStatus[3] . "A available)";
                                }
                            }
                        }
                    }
                    print "</p>";

                    // Connected vehicles and their approval state
                    $vinResponse = ipcQuery('getVINs');
                    if($vinResponse != '') {
                        print '<p style="margin-top:1.5em; margin-bottom:0.3em"><strong>Connected vehicles</strong></p>';
                        foreach(explode('`', $vinResponse) as $entry) {
                            $v = explode('~', $entry);
                            if(count($v) < 3 || $v[1] == '') { continue; }
                            $vin = $v[1];
                            $expiry = intval($v[2]);
                            print '<p style="margin:0.3em 0">TWC ' . htmlspecialchars($v[0]) . ': '
                                . '<code>' . htmlspecialchars($vin) . '</code> ';
                            if($expiry == 0) {
                                print '<span style="color:#080">approved</span> ';
                            } elseif($expiry > time()) {
                                print '<span style="color:#080">approved until '
                                    . date('H:i d-m', $expiry) . '</span> ';
                            } else {
                                print '<span style="color:#c00">not approved</span> ';
                            }
                            print '<a href="index.php?approveVIN=' . urlencode($vin) . '&hours=0&submit=1">[always]</a> ';
                            print '<a href="index.php?approveVIN=' . urlencode($vin) . '&hours=24&submit=1">[24h]</a> ';
                            print '<a href="index.php?revokeVIN=' . urlencode($vin) . '&submit=1">[revoke]</a>';
                            print '</p>';
                        }
                    }
                }

                if($twcModelMaxAmps < 40) {
                    // The last TWC in the list reported supporting under 40
                    // total amps. Assume this is a 32A EU TWC and offer
                    // appropriate values. You can add or remove values, just
                    // make sure they are whole numbers between 5 and
                    // $twcModelMaxAmps.
                    // Nietschy pointed out that his car was limited to 16A by
                    // onboard chargers, but setting the TWC to 16A leads to
                    // 15.7A actual usage.  When set to 17A, the car is able to
                    // draw a little more power, so we offer 17A instead of 16A
                    // below.
                    $use24HourTime = true;
                    $aryStandardAmps = array(
                                            '6A' => '6',
                                            '8A' => '8',
                                            '10A' => '10',
                                            '13A' => '13',
                                            '16A' => '16',
                                            '17A' => '17',
                                            '21A' => '21',
                                            '25A' => '25',
                                            '32A' => '32',
                                        );
                }
                else {
                    // Offer values appropriate for an 80A North American TWC
                    $use24HourTime = false;
                    $aryStandardAmps = array(
                                            '6A' => '6',
                                            '8A' => '8',
                                            '12A' => '12',
                                            '16A' => '16',
                                            '20A' => '20',
                                            '24A' => '24',
                                            '28A' => '28',
                                            '32A' => '32',
                                            '36A' => '36',
                                            '40A' => '40',
                                            '48A' => '48',
                                            '56A' => '56',
                                            '64A' => '64',
                                            '72A' => '72',
                                            '80A' => '80',
                                        );
                }

                // Remove amp values higher than the value of
                // $wiringMaxAmpsAllTWCs or lower than $minAmpsPerTWC set in
                // TWCManager.py.
                foreach($aryStandardAmps as $key => $value) {
                    if($value > $wiringMaxAmpsAllTWCs || $value < $minAmpsPerTWC) {
                        unset($aryStandardAmps[$key]);
                    }
                }
            ?>
        </td>
        <td valign="middle">
            <input type="image" alt="Refresh" src="refresh.png" style="margin-left:1em">
        </td>
    </tr></table>
    </form>
</div>
<br />
<div style="display: inline-block; text-align:right;">
    <form action="index.php" name="setAmps" method="get">
        <p style="margin-bottom:0; margin-top:1.8em;">
            <strong>(Non-scheduled) Power:</strong>
            <?php
                DisplaySelect('nonScheduledAmpsMax', '', array_merge(array('Do not charge' => '0'), $aryStandardAmps));
            ?>
        </p>
        <p style="margin-top:1.8em; text-align:right;">
            <?php
            if($chargeNowAmps > 0) {
                print '<input type="submit" name="submit" value="Cancel 24-hour-charge">';
            }
            else {
                print '<input type="submit" name="submit" value="24-hour-charge, '
                    . sprintf("%.0f", $wiringMaxAmpsAllTWCs) . 'A">';
            }
            ?>
            <input type="submit" name="submit" value="Save">
        </p>
    </form>
</div>

<?php
    function ipcCommand($ipcCommand)
    // Send an IPC command to TWCManager.py.  A command does not expect a
    // response.
    {
        global $ipcQueue, $debugLevel;
        $ipcErrorCode = 0;
        $ipcMsgID = 0;
        $ipcMsgTime = time();

        ipcSend($ipcMsgTime, $ipcMsgID, $ipcCommand);
    }

    function ipcQuery($ipcMsgSend, $usePackets = false)
    // Send an IPC query to TWCManager.py and wait for a response which we
    // return.
    {
        global $ipcQueue, $debugLevel;
        $ipcErrorCode = 0;

        // There could be multiple web pages or other interfaces sending queries
        // to TWCManager.py.  To help ensure we get back the response to our
        // particular query, assign a random ID to our query and only accept
        // responses containing the same ID.
        $ipcMsgID = rand(1,65535);

        // Also add a timestamp to our query.  Messages unprocessed for too long
        // will be discarded.
        $ipcMsgTime = time();

        // Send our query
        if(ipcSend($ipcMsgTime, $ipcMsgID, $ipcMsgSend) == false) {
            return '';
        }

        // Wait up to 15 seconds for a response.
        $ipcMsgType = 0;
        $ipcMsgRecv = '';
        $ipcMaxMsgSize = 300;
        $i = 0;
        $maxRetries = 150;
        $numPackets = 0;
        $msgResult = '';
        for(; $i < $maxRetries; $i++) {
            // MSG_NOERROR flag prevents showing an error if there are too many
            // characters and some were lost.
            if(msg_receive($ipcQueue, 1, $ipcMsgType, $ipcMaxMsgSize, $ipcMsgRecv, false,
                           MSG_IPC_NOWAIT | MSG_NOERROR, $ipcErrorCode) == false
            ) {
                // Error 42 means no response is available yet, which is likely to happen
                // briefly.
                if($ipcErrorCode != 42) {
                    print("Message receive failed with error code $ipcErrorCode<br>");
                }
            }
            else {
                $aryMsg = unpack("Ltime/SID/a*msg", $ipcMsgRecv);
                if($debugLevel >= 10) {
                   print "ipcQuery received '" . $aryMsg['msg'] . "', id " . $aryMsg['ID']
                           . ", time " . $aryMsg['time'] . "<p>";
                }

                if($aryMsg['ID'] == $ipcMsgID) {
                    // This response matches our message ID
                    if($usePackets) {
                        if($numPackets == 0) {
                            $numPackets = ord($aryMsg['msg']);
                            if($debugLevel >= 10) {
                                print "ipcQuery numPackets $numPackets<p>";
                            }
                        }
                        else {
                            $msgResult .= $aryMsg['msg'];
                            $numPackets--;
                            if($numPackets == 0) {
                                return $msgResult;
                            }
                        }
                        continue;
                    }
                    else {
                        return $aryMsg['msg'];
                    }
                }
                if(time() - $aryMsg['time'] < 30) {
                    // Message ID doesn't match the ID of our query so this
                    // isn't a response to our query. However, this message is
                    // less than 30 seconds old so another process may still be
                    // waiting for it. Therefore, we put it back at the end of
                    // the message queue.
                    if($debugLevel >= 10) {
                        print "ipcQuery: Put unexpired message back at end of queue.<br>";
                    }
                    ipcSend($aryMsg['time'], $aryMsg['ID'], $aryMsg['msg'], 1);
                }
            }

            // Sleep 1/10 of a second, then check again for a response.
            usleep(100000);
        }

        if($i >= $maxRetries) {
            print "<span style=\"color:#F00; font-weight:bold;\">"
                . "Timed out waiting for response from TWCManager script.</span><p>"
                . "If the script is running, make sure the \$twcScriptDir parameter "
                . "in the source of this web page points to the directory containing "
                . "the TWCManager script.</p><p>";
        }
        return '';
    }

    function ipcSend($ipcMsgTime, $ipcMsgID, $ipcMsg, $ipcMsgType = 2)
    // Help ipcCommand or ipcQuery send their IPC message. Don't call this
    // directly.
    // Most messages we send to TWCManager.py will use $ipcMsgType = 2 while
    // responses to queries will use $ipcMsgType = 1. I picked those values
    // thinking I might use type 1 for responses to queries and values 2 and
    // higher to distinguish different commands or queries but decided to use
    // clear English messages.
    {
        global $ipcQueue, $debugLevel;

        if($debugLevel >= 10) {
            if($debugLevel >= 10) {
                print "ipcQuery sending '" . $ipcMsg . "', id " . $ipcMsgID
                        . ", time " . $ipcMsgTime . "<p>";
            }

            if($debugLevel >= 11) {
                // Print binary bytes in the message if debugging requires.
                print "ipcSend binary message of length " . strlen($ipcMsgSend) . ': ';
                for($i = 0; $i < strlen($ipcMsgSend); $i++) {
                    printf("%02x ", ord(substr($ipcMsgSend, $i, 1)));
                }
                print("<p>");
            }
        }

        if(msg_send($ipcQueue, $ipcMsgType, pack("LSa*", $ipcMsgTime, $ipcMsgID, $ipcMsg),
                    false, false, $ipcErrorCode) == false
        ) {
            print("Couldn't send '$ipcMsgSend'.  Error code $ipcErrorcode.<br><br>");
            return false;
        }
        return true;
    }


    function DisplaySelect($name, $selectExtraParams, $valueArray, $defaultKey = "")
    // Display an HTML form <select><option>...</option></select> block using
    // values from $valueArray.
    {
        print "<SELECT name=\"$name\"" . $selectExtraParams . " id=\"$name\">\n";
        foreach($valueArray as $key => $value) {
            print "<OPTION value=\"$value\"";
            // Use === and string casting or else "0" == "" will be found true
            if(((string)$GLOBALS[$name]) === ((string)$value) ||
                ( ((string)$GLOBALS[$name]) === "" && $key === $defaultKey )) {
                print " selected";
            }
            print " autocomplete=\"off\">$key</OPTION>\n";
        }
        print "</SELECT>\n";
    }

    function DisplayCheckbox($name, $extraParams, $value)
    {
        print '<INPUT type="checkbox" name="' . $name . '" value="' . $value . '"';
        if( ((string)$GLOBALS[$name]) === ((string)$value) ) {
            print " checked";
        }
        if($extraParams != '') {
            print $extraParams;
        }
        print '>';
    }
?>
</body>
</html>
