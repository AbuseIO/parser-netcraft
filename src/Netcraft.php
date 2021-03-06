<?php

namespace AbuseIO\Parsers;

use AbuseIO\Models\Incident;

/**
 * Class Netcraft
 * @package AbuseIO\Parsers
 */
class Netcraft extends Parser
{
    /**
     * Create a new Netcraft instance
     *
     * @param \PhpMimeMailParser\Parser $parsedMail phpMimeParser object
     * @param array $arfMail array with ARF detected results
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        foreach ($this->parsedMail->getAttachments() as $attachment) {
            if (preg_match(config("{$this->configBase}.parser.report_file"), $attachment->getFilename())) {
                if (preg_match_all(
                    '/([\w\-]+): (.*)[ ]*\r?\n/',
                    str_replace("\r", "", $attachment->getContent()),
                    $matches
                )) {
                    $report = array_combine($matches[1], $matches[2]);

                    // We need this field to detect the feed, so we need to check it first
                    if (!empty($report['Report-Type'])) {
                        // Handle aliasses first
                        foreach (config("{$this->configBase}.parser.aliases") as $alias => $real) {
                            if ($report['Report-Type'] == $alias) {
                                $report['Report-Type'] = $real;
                            }
                        }

                        $this->feedName = $report['Report-Type'];

                        // If feed is known and enabled, validate data and save report
                        if ($this->isKnownFeed() && $this->isEnabledFeed()) {
                            switch ($report['Source-Type']) {
                                case 'uri':
                                    // Match case 1:
                                    // A single line with 'http* [x.x.x.x]' (note the space)
                                    preg_match(
                                        '/\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]/',
                                        $this->parsedMail->getMessageBody(),
                                        $matches
                                    );
                                    if (count($matches) == 2 && empty($report['Ip'])) {
                                        $report['Ip'] = $matches[1];
                                    }

                                    // Match case 2:
                                    // Somewhere a line will end (watch out for mime split!) 'address x.x.x.x.'
                                    preg_match(
                                        '/address ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\./',
                                        $this->parsedMail->getMessageBody(),
                                        $matches
                                    );
                                    if (count($matches) == 2 && empty($report['Ip'])) {
                                        $report['Ip'] = $matches[1];
                                    }

                                    // Match case 3:
                                    // IPv6 report
                                    if (preg_match(
                                        '/(?>(?>([a-f0-9]{1,4})(?>:(?1)){7}|'.
                                        '(?!(?:.*[a-f0-9](?>:|$)){8,})((?1)(?>:(?1)){0,6})?::(?2)?)|(?>('.
                                        '?>(?1)(?>:(?1)){5}:|(?!(?:.*[a-f0-9]:){6,})(?3)?::(?>((?1)(?>:('.
                                        '?1)){0,4}):)?)?(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?>\.(?4)){3}))/',
                                        $this->parsedMail->getMessageBody(),
                                        $matches
                                    )) {
                                        $report['Ip'] = $matches[0];
                                    }
                                    break;
                                case 'ipv4':
                                case 'ipv6':
                                case 'ip-address':
                                default:
                                    $report['Ip'] = $report['Source'];
                                    break;
                            }

                            // Sanity check
                            if ($this->hasRequiredFields($report) === true) {
                                // incident has all requirements met, filter and add!
                                $report = $this->applyFilters($report);

                                // Manually update some fields for easier handling
                                if ($report['Report-Type'] == 'phishing') {
                                    $url = $report['Source'];
                                }

                                if ($report['Report-Type'] == 'malware-attack') {
                                    // Download-Link to Domain / Uri
                                    $url = $report['Download-Link'];
                                }

                                $incident = new Incident();
                                $incident->source      = config("{$this->configBase}.parser.name");
                                $incident->source_id   = false;
                                $incident->ip          = $report['Ip'];
                                $incident->domain      = empty($url) ? false : getDomain($url);
                                $incident->class       = config("{$this->configBase}.feeds.{$this->feedName}.class");
                                $incident->type        = config("{$this->configBase}.feeds.{$this->feedName}.type");
                                $incident->timestamp   = strtotime($report['Date']);
                                $incident->information = json_encode($report);

                                $this->incidents[] = $incident;

                            }
                        }
                    }
                }
            }
        }

        return $this->success();
    }
}
