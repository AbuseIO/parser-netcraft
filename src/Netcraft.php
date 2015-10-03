<?php

namespace AbuseIO\Parsers;

use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;

class Netcraft extends Parser
{
    /**
     * Create a new Blocklistde instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        foreach ($this->parsedMail->getAttachments() as $attachment) {
            if ($attachment->filename != 'report.txt') {
                continue;
            }

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

                        /*
                         * Retrieve the IP from the body, as xARF only allows a single source and netcraft is the
                         * only one actually sticking to the specifications. Sadly they use multiple templates we
                         * need to consider to collect the IP address from:
                         */

                        /*
                         * Match case 1, a single line with 'http* [x.x.x.x]' (note the space)
                         * This case is related to the normal ISP notifications
                         */
                        preg_match(
                            '/\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]/',
                            $this->parsedMail->getMessageBody(),
                            $matches
                        );
                        if (count($matches) == 2 && empty($report['ip'])) {
                            $report['ip'] = $matches[1];
                        }

                        /*
                         * Match case 2, somewhere a line will end (watch out for mime split!) 'address x.x.x.x.'
                         * This case is related to the upstream ISP notifications
                         */
                        preg_match(
                            '/address ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\./',
                            $this->parsedMail->getMessageBody(),
                            $matches
                        );
                        if (count($matches) == 2 && empty($report['ip'])) {
                            $report['ip'] = $matches[1];
                        }

                        // Sanity check
                        if ($this->hasRequiredFields($report) === true) {
                            // Event has all requirements met, filter and add!
                            $report = $this->applyFilters($report);

                            // Manually update some fields for easier handling
                            if ($report['Report-Type'] == 'phishing') {
                                $report['uri'] = str_replace(
                                    $report['Service']."://".$report['Domain'],
                                    "",
                                    $report['Source']
                                );
                            }

                            if ($report['Report-Type'] == 'malware-attack') {
                                // Download-Link to domain/uri
                                $url_info = parse_url($report['Download-Link']);
                                if (!empty($url_info['host'])) {
                                    $report['Domain'] = $url_info['host'];
                                } else {
                                    $report['Domain'] = false;
                                }
                                if (!empty($url_info['path'])) {
                                    $report['uri'] = $url_info['path'];
                                } else {
                                    $report['uri'] = false;
                                }
                            }

                            $this->events[] = [
                                'source'        => config("{$this->configBase}.parser.name"),
                                'ip'            => $report['ip'],
                                'domain'        => $report['Domain'],
                                'uri'           => $report['uri'],
                                'class'         => config("{$this->configBase}.feeds.{$this->feedName}.class"),
                                'type'          => config("{$this->configBase}.feeds.{$this->feedName}.type"),
                                'timestamp'     => strtotime($report['Date']),
                                'information'   => json_encode($report),
                            ];
                        }
                    }
                }
            }
        }

        return $this->success();
    }
}
