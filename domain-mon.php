<?php set_time_limit(570); //9m 30s

//Handle program arguments
if(!isset($argv[1])) {
    print("No argument specified. Use the `--help` argument for help.\n");
    exit(2);
}
//Handle non-mandatory options
$prependHeaders = false;
$fullReport = false;
$sleepTime = 1;
for($arg = 1; $arg < count($argv); ++$arg) {
    switch($argv[$arg]) {
        case "--directory":
        case "-d":
            if(is_dir($argv[++$arg])) {
                chdir($argv[$arg]);
            } else {
                print("Unable to set directory to '" . $argv[$arg] . "'. No such file or directory.\n");
                exit(1);
            }
            break;
        case "--full":
        case "-f":
            $fullReport = true;
            break;
        case "--help":
        case "-h":
        case "-?":
        case "?":
            helpText();
            exit(0);
        case "--max-exec-time":
        case "-m":
            switch(true) {
                case filter_var($argv[++$arg], FILTER_VALIDATE_INT, array("options" => array("min_range" => 1))):
                    set_time_limit($argv[$arg]);
                    break;
                case $argv[$arg] === "0":
                    set_time_limit(0);
                    break;
                default:
                    print("Invalid argument for '" . $argv[--$arg] . "'.\n");
                    exit(1);
            }
            break;
        case "--smtp-headers":
        case "-s":
            $prependHeaders = true;
            break;
        case "--wait":
        case "-w":
            switch(true) {
                case filter_var($argv[++$arg], FILTER_VALIDATE_INT, array("options" => array("min_range" => 1))):
                    $sleepTime = $argv[$arg];
                    break;
                case $argv[$arg] === "0":
                    $sleepTime = 0;
                    break;
                default:
                    print("Invalid argument for '" . $argv[--$arg] . "'.\n");
                    exit(1);
            }
            break;
    }
}

//Load config
if(file_exists("config.ini")) {
    //Parse config.ini file
    set_error_handler("configIniWarningHandler", E_WARNING);
    $configIni = parse_ini_file("config.ini");
    restore_error_handler();
    
    //Check that all expected config values are present
    foreach(array("time_zone", "custom_name", "from_address", "to_address") as $configValue) {
        if(!isset($configIni[$configValue])) {
            print("Config value '" . $configValue . "' is missing. Please verify the syntax of config.ini.\n");
            exit(1);
        }
    }

    //Override custom_name if it is blank
    if(!$configIni["custom_name"]) {
        $configIni["custom_name"] = "Domain Monitor";
    }

    //Validate 'from' and 'to' email addresses
    //If both configuration values are empty, omit email headers
    if(($configIni["from_address"] === "") && ($configIni["to_address"] === "")) {
        $prependHeaders = false;
    //Else, check whether email addresses are valid
    } else {
        foreach(array("from_address", "to_address") as $configValue) {
            if(!filter_var($configIni[$configValue], FILTER_VALIDATE_EMAIL)) {
                print("Invalid '" . $configValue . "' value: '" . $configIni[$configValue] . "'. Please use a valid email address.\n");
                exit(1);
            }
        }
    }

    //Validate and set time zone for timestamps in reports
    if(in_array($configIni["time_zone"], DateTimeZone::listIdentifiers())) {
        date_default_timezone_set($configIni["time_zone"]);
    } else {
        print("Invalid time zone value: '" . $configIni["time_zone"] . "'. Please use a valid time zone string from the IANA Time Zone Database. E.g. 'Europe/London'.\n");
        exit(1);
    }
} else {
    print("Unable to find program config file in '" . getcwd() . "'. Please change your working directory to that of the program, e.g. using 'cd', or manually override the working directory using the '--directory' argument.\n\nIf you haven't set up a config file yet, please copy 'config.ini.example' to 'config.ini' in the program directory and adjust the default options as required.\n");
    exit(2);
}

//Load list of domain names to monitor
if(file_exists("domains.txt")) {
    $domains = file("domains.txt", FILE_IGNORE_NEW_LINES);
} else {
    print("Unable to find domain name list in '" . getcwd() . "'. Please create 'domains.txt' and specify the domain names to monitor, one per line. For example:\n\nexample.com\nexample.org\nexample.net\n");
    exit(2);
}

//Load expiries file
if(file_exists("expiries.json")) {
    $expiries = json_decode(file_get_contents("expiries.json"));
    if(json_last_error() !== JSON_ERROR_NONE) {
        print("File 'expiries.json' is invalid. Please verify the JSON syntax.\n");
        exit(2);
    }
} else {
    $expiries = new stdClass();
}

//Get current time
$now = new DateTime('now');

$nullVar = null; //For stream_select() as variables must be passed as references
$results = [];
$unableToCheck = [];

switch($argv[1]) {
    case "update": {
        if(!isset($argv[2])) { //Mandatory argument
            print("Please specify an argument for 'update'.\n");
            exit(1);
        }
        switch(true) { //Switch against true to allow for validating non-static argument
            case filter_var($argv[2], FILTER_VALIDATE_INT, array("options" => array("min_range" => 1))):
                update((int)($argv[2]));
                break;
            case $argv[2] === "all":
                update(count($domains));
                break;
            default:
                print("Invalid argument for 'update'.\n");
                exit(1);
        }
        break;
    } case "report": {
        print(generateReport($prependHeaders, $fullReport));
        break;
    } default:
        print("Invalid argument. Use the `--help` argument for help.\n");
        exit(1);
}

//Custom warning handler for parsing config file
function configIniWarningHandler(int $errno, string $errstr) {
    print("An error occurred while parsing config.ini.\n\nError output:\n\n" . $errstr . "\n");
    exit(2);
}

//Custom warning handler for WHOIS fsock/stream
function whoisWarningHandler(int $errno, string $errstr) {
    print("An error occurred when connecting to the WHOIS server.\n\nError output:\n\n" . $errstr . "\n");
    exit(2);
}

//Writes list of expiry dates to expiries.json
function writeExpiries(object $expiries) {
    file_put_contents('expiries.json', json_encode($expiries));
}

//Returns the first-level TLD for a domain
function getTld(string $domain) {
    //If domain contains dot, find TLD and return it
    if(strpos($domain, ".")) {
        return pathinfo($domain, PATHINFO_EXTENSION);
    //If domain doesn't contain a dot, just return domain as-is
    } else {
        return $domain;
    }
}

//Returns raw WHOIS data for $domain
function whois(string $domain) {
    print("Checking expiry for '" . $domain . "'...\n");
    //Special case for gov.uk domains, as they use JANET whois
    if(substr($domain, -7) === ".gov.uk") {
        $whoisServer = "whois.ja.net";
    //Standard domain names
    } else {
        $whoisServer = getTld($domain) . ".whois-servers.net";
    }
    print("Connecting to '" . $whoisServer . "'...\n");
    set_error_handler("whoisWarningHandler", E_WARNING);
    $whois = fsockopen($whoisServer, 43);
    restore_error_handler();
    stream_set_timeout($whois, 3);
    stream_set_blocking($whois, true);
    fwrite($whois, $domain . "\r\n");
    $read = [$whois];
    $retries = 1;
    while(stream_select($read, $nullVar, $nullVar, 5) === false) {
        if($retries++ >= 5) {
            return 0;
        }
        print("Retrying... (attempt " . $retries . ")");
        sleep(1);
    }
    $whoisRecord = filter_var(stream_get_contents($whois, 65535), FILTER_DEFAULT, FILTER_FLAG_STRIP_HIGH);
    fclose($whois);
    return $whoisRecord;
}

//Returns expiry date for $whoisResult in Y-m-d format
function parseExpiry(string $whoisResult) {
    try {
        //Match expiry string in raw WHOIS result, and return ERR_NO_DATE if not found
        
        //Most common WHOIS record format (e.g. com, org, net, uk, etc)
        if(preg_match("/expiry date.*/i", $whoisResult, $expiryString)) {
            $match = " ";
        //Special case for gov.uk domains, where the expiry date is on a new line under 'Renewal date:'
        } elseif(preg_match("/renewal date:\n.*/i", $whoisResult, $expiryString)) {
            $match = "\t";
        } else {
            return 0;
        }
        //Trim expiry string to prevent output issues with control characters/line endings in some shells
        $expiryString[0] = trim($expiryString[0]);
        print("Found raw expiry date string: \"" . $expiryString[0] . "\"\n");
        //Extract date string from raw WHOIS result
        $expiryDateString = substr($expiryString[0], strrpos($expiryString[0], $match)+1);        
        print("Extracted date from raw string: \"" . $expiryDateString . "\"\n");
        //Create DateTime object based on extracted date
        $expiryDate = (new DateTime($expiryDateString))->format('Y-m-d');
        print("Parsed expiry date as: \"" . $expiryDate . "\" (YYYY-MM-DD)\n");
        return $expiryDate;
    } catch(Exception $exception) {
        print("\nERROR: Unable to parse date: \"" . $expiryString[0] . "\"\nCaught exception: " . $exception->getMessage() . "\n");
        return 0;
    }
}

//Returns an array with $domain, $expiryDate
function getExpiry(string $domain) {
    $expiryDate = parseExpiry(whois($domain));
    if($expiryDate) {
        print("\n[-*-] " . $domain . " expires on " . $expiryDate . ".\n\n");
        return [$domain, $expiryDate];
    } else {
        print("\n[-!-] Unable to find expiry date for " . $domain . ".\n\n");
        return [$domain, "ERR_NO_DATE"];
    }
}

//Generates a domain expiry report using the latest data
function generateReport(bool $prependHeaders, bool $outputAll) {
    global $now, $expiries, $domains, $configIni;
    //Calculate days until expiry for each domain
    $removedDomains = false;
    foreach($expiries as $domain => $expiry) {
        //Check for domains that have been removed from the domains list, therefore shouldn't be included in the report
        if(!in_array($domain, $domains)) {
            unset($expiries->$domain);
            $removedDomains = true;
        }
        //Check for domains where the expiry date was unable to be checked
        if($expiry === "ERR_NO_DATE") {
            $results[$domain] = array("Unable to find renewal date.", "error");
        //Calculate days until expiry
        } else {
            $expiryDate = new DateTime($expiry);
            $results[$domain] = array($expiry, $now->diff($expiryDate)->format("%r%a"));
            //Check for domains expiring today, and switch day count from "-0" to "0"
            if($results[$domain][1] === "-0") {
                $results[$domain][1] = "0";
            }
        }
    }
    //Update expiries list if required
    if($removedDomains=== true) {
        writeExpiries($expiries);
    }
    //Sort the results chronologically
    asort($results);
    //Create arrays to allow reading in foreach without a notice
    $reportLists = [];
    foreach(array("expired", "_7days", "_28days", "_90days", "_90plus", "errors") as $arrayName) {
        $$arrayName = [];
    }
    //Create arrays of expiries within 7, 28 and 90 days
    $hasExpiries = 0;
    foreach($results as $domain => $expiry) {
        switch(true) {
            case $expiry[1] === "error":
                $errors[$domain] = $expiry;
                break;
            case $expiry[1] < 0:
                $expired[$domain] = $expiry;
                $hasExpiries = 1;
                break;
            case $expiry[1] <= 7:
                $_7days[$domain] = $expiry;
                $hasExpiries = 1;
                break;
            case $expiry[1] <= 28:
                $_28days[$domain] = $expiry;
                $hasExpiries = 1;
                break;
            case $expiry[1] <= 90:
                $_90days[$domain] = $expiry;
                $hasExpiries = 1;
                break;
            default:
                $_90plus[$domain] = $expiry;
        }
    }
    //Create an array of lists to report on
    $reportLists = [$expired, $_7days, $_28days, $_90days, $errors];
    $reportListTypes = ["expired", "7", "28", "90", "errors"];
    if($outputAll) {
        //Insert _90plus array into report lists
        array_splice($reportLists, 4, 0, array($_90plus));
        array_splice($reportListTypes, 4, 0, "90+");
    }
    //Define list header string
    $listHead = "<tr><th><b>[Domain Name]</b></th><th><b>[Expiry Date]</b></th></tr>\n";
    $errorHead = "<tr><th><b>[Domain Name]</b></th><th><b>[Error Description]</b></th></tr>\n";
    //Define report variable
    $report = "";
    //Email headers
    if($prependHeaders) {
        $report .= "From: " . $configIni["custom_name"] . " <" . $configIni["from_address"] . ">
To: " . $configIni["to_address"] . "
Subject: " . $configIni["custom_name"] . " Report for " . $now->format('Y-m-d g:i:s A') . "
Content-Type: text/html
Content-Disposition: inline\n\n";
    }    
    //Begin constructing report string
    $report .= "<html>
<head>
<style>th { text-align: left; padding-right: 120px; }
th,td { padding-left: 0; }
.no-mar-top { margin-top: 0 }</style>
</head>
<body>\n
<p>Hi,</p>\n\n";
    if($hasExpiries === 0) {
        $report .= "<p>No domain names are due for renewal within the next 90 days.</p>\n\n";
    }
    $looped = 0;
    foreach($reportLists as $key => $list) {
        $count = count($list);
        if(count($list) > 0) {
            //Select the summary text to output
            if($reportListTypes[$key] === "expired") {
                $report .= "<p>The following " . ($count > 1 ? $count . " " : "") . "domain " . ($count > 1 ? "names have" : "name has") . " EXPIRED!</p>\n";
            } elseif($reportListTypes[$key] !== "errors") {
                $report .= "<p>There " . ($count > 1 ? "are" : "is") . " " . ($looped === 1 ? "another " : "") . $count . " domain name " . ($count > 1 ? "renewals" : "renewal") . " requiring " . ($reportListTypes[$key] === "7" ? "<u>urgent</u> " : "") . "action within the next " . $reportListTypes[$key] . " days:</p>\n";
            } else {
                $report .= "<p>" . $configIni["custom_name"] . " encountered problems checking the following " . ($count > 1 ? $count . " " : "") . "domain " . ($count > 1 ? "names" : "name") . ":</p>\n";
            }
            //Select the expiries list to output
            $report .= "<table>\n";
            if($reportListTypes[$key] !== "errors") {
                $report .= $listHead;
                foreach($list as $domain => $expiry) {
                    $report .= "<tr><td>" . $domain . "</td><td>" . $expiry[0] . " (" . $expiry[1] . " days)</td></tr>\n";
                }
            } else {
                $report .= $errorHead;
                foreach($list as $domain => $expiry) {
                    $report .= "<tr><td>" . $domain . "</td><td>" . $expiry[0] . "</td></tr>\n";
                }
            }
            $report .= "</table>\n\n";
            $looped = 1;
        }
    }
    if($hasExpiries === 1) {
        $count = count($_90plus);
        $report .= "<p>There " . ($count > 1 ? "are" : "is") . " " . $count . " domain " . ($count > 1 ? "names" : "name") . " not yet due for renewal, and a";
    } else {
        $report .= "<p>There is a";
    }
    $count = count($domains);
    $report .= " total of " . $count . " domain " . ($count > 1 ? "names" : "name" ) . " in the monitoring list.</p>

<p>Thank you,<br/>
" . $configIni["custom_name"] . "</p>\n
</body>
</html>";
    return $report;
}

//Updates the $expiries array with $result
function recordExpiry(array $result) {
    global $expiries;
    $expiries->{$result[0]} = $result[1];
}

//Update $count domain names
function update(int $count) {
    global $domains, $expiries, $now, $sleepTime;
    if($count > count($domains)) {
        $count = count($domains);
    }
    print("Updating " . $count . " domain(s) at " . $now->format('Y-m-d g:i:s A') . "...\n\n");
    //Validate domains.txt file
    foreach($domains as $key => $domain) {
        //Remove trailing dots, as they are not needed in this case
        if(substr($domain, -1) === ".") {
            $domains[$key] = rtrim($domain, ".");
            $domain = rtrim($domain, ".");
        }
        //Remove empty lines - this is after the removal of trailing dots, as sometimes removing trailing dots can result in an empty line (e.g. if the line is just ".")
        if($domain === "") {
            unset($domains[$key]);
        //Check for valid domain name
        } elseif(!filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            print("Validation of domains.txt failed. '" . trim($domain) . "' is invalid.\n");
            exit(2);
        }
    }
    //Exit if there are no valid domains in domains.txt
    if(empty($domains)) {
        print("There are no valid domains in domains.txt.\n");
        exit(2);
    }
    //Check for duplicate lines in domains.txt
    $duplicates = array_diff_assoc($domains, array_unique($domains));
    if($duplicates) {
        print("Duplicate value(s) found in domains.txt:\n\n");
        foreach($duplicates as $line => $duplicate) {
            print(" * " . $duplicate . " (Line " . ($line + 1) . ")\n");
        }
        print("\nPlease remove the duplicates to continue.\n");
        exit(2);
    }
    //Sort array, to reorder it if any keys have been removed
    $domains = array_values($domains);
    //Load last updated file and set 'read head'
    if(file_exists("head.txt")) {
        $lastUpdated = rtrim(file_get_contents('head.txt'));
        $head = array_search($lastUpdated, $domains);
        if($head === false) {
            print("Domain under head ('" . $lastUpdated . "') cannot be found (it may have been manually removed from the domains list) - resetting head to 0.\n");
            $head = 0;
        } else {
            print("Domain under head (" . $lastUpdated . ") found at position " . $head . ".\n");
        }
    } else {
        $head = 0;
    }
    $total = 1;
    //Check expiries for domains
    for($head; $head < count($domains); $head++) {
        recordExpiry(getExpiry($domains[$head]));
        if($head >= count($domains)-1) {
            print("Reached end of domain list, resetting head to start...\n\n");
            $head = -1;
        }
        if($total++ >= $count) {
            print("Updated " . $count . " domain(s).\n");
            $head++;
            break;
        }
        if($sleepTime !== 0 && $count > 1) {
            print("Sleeping for " . $sleepTime . " seconds...\n\n");
            sleep($sleepTime);
        }
    }
    //Write head back to file
    $newHead = $domains[$head];
    print("Setting head to '" . $newHead . "' (position " . $head . ").\n");
    file_put_contents('head.txt', $domains[$head]);
    //Write expiries file
    writeExpiries($expiries);
}

//Help text isn't included as a separate file to ensure that it can always be accessed, no matter what the working directory of the program is
function helpText() {
    print("Usage: domain-mon.php [COMMAND] [OPTIONS]...

Commands and options:

  report              Output a 90 day domain name expiry report.
    -f, --full        Output a full domain name expiry report.
    -s, --smtp-headers  Output a report with prepended email headers.

  update              Update domain name expiry dates.
    [int >= 1]        Update [int] expiry dates.
    all               Update all expiry dates.
    -w, --wait        Delay, in seconds, between WHOIS requests. Default: 1

  -d, --directory     Override the working directory of the program. Useful if you want to run the program without having to 'cd' into the program directory.
  -h, --help          Display this help text.
  -m, --max-exec-time Maximum execution time, in seconds. Default: 570 (9m 30s)

Example usage:

  Update 3 domain name expiry dates:

    $ domain-mon.php update 3

  Update all domain name expiry dates (not recommended as you may hit WHOIS server rate limits):

    $ domain-mon.php update all

  Produce a 90 day domain name expiry report:

    $ domain-mon.php report

  Produce a 90 day domain name expiry report with prepended email headers:

    $ domain-mon.php report --smtp-headers

  Produce a full domain name expiry report:

    $ domain-mon.php report --full

  Produce a full domain name expiry report with prepended email headers:

    $ domain-mon.php report --full --smtp-headers
    
  Run the program using a different configuration directory:

    $ domain-mon.php report --directory \"/home/user/domain-mon/\"

Exit status:

  0 if OK
  1 if minor problems (e.g. invalid argument)
  2 if major problems (e.g. error)
");
} ?>