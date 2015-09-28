<?php

namespace AbuseIO\Parsers;

use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;
use Log;
use ReflectionClass;

class Netcraft extends Parser
{
    public $parsedMail;
    public $arfMail;

    /**
     * Create a new Blocklistde instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        $this->parsedMail = $parsedMail;
        $this->arfMail = $arfMail;
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        // Generalize the local config based on the parser class name.
        $reflect = new ReflectionClass($this);
        $this->configBase = 'parsers.' . $reflect->getShortName();

        Log::info(
            get_class($this) . ': Received message from: ' .
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config("{$this->configBase}.parser.name")
        );

        $events = [ ];

        foreach ($this->parsedMail->getAttachments() as $attachment) {
            if ($attachment->filename != 'report.txt') {
                continue;
            }

            preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', str_replace("\r", "", $attachment->getContent()), $regs);
            $report = array_combine($regs[1], $regs[2]);

            // We need this field to detect the feed, so we need to check it first
            if (empty($report['Report-Type'])) {
                return $this->failed(
                    "Unable to detect feed because the required field Report-Type is missing."
                );
            }

            // Handle aliasses first
            foreach (config("{$this->configBase}.parser.aliases") as $alias => $real) {
                if ($report['Report-Type'] == $alias) {
                    $report['Report-Type'] = $real;
                }
            }

            $this->feedName = $report['Report-Type'];

            if (!$this->isKnownFeed()) {
                return $this->failed(
                    "Detected feed {$this->feedName} is unknown."
                );
            }

            if (!$this->isEnabledFeed()) {
                continue;
            }

            // Retrieve the IP from the body, as xARF only allows a single source and netcraft is the only one actually
            // sticking to the specifications. Sadly they use multiple templates we need to consider to full the IP
            // address from.
            // Match case 1, a single line with 'http* [x.x.x.x]' (note the space)
            // This case is related to the normal ISP notifications
            preg_match(
                '/\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]/',
                $this->parsedMail->getMessageBody(),
                $matches
            );
            if (count($matches) == 2 && empty($report['ip'])) {
                $report['ip'] = $matches[1];
            }

            // Match case 2, somewhere a line will end (watch out for mime split!) 'address x.x.x.x.'
            // This case is related to the upstream ISP notifications
            preg_match(
                '/address ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\./',
                $this->parsedMail->getMessageBody(),
                $matches
            );
            if (count($matches) == 2 && empty($report['ip'])) {
                $report['ip'] = $matches[1];
            }

            if (!$this->hasRequiredFields($report)) {
                return $this->failed(
                    "Required field {$this->requiredField} is missing or the config is incorrect."
                );
            }

            $report = $this->applyFilters($report);

            // Manually update some fields for easier handling
            if ($report['Report-Type'] == 'phishing') {
                $report['uri'] = str_replace($report['Service']."://".$report['Domain'], "", $report['Source']);
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

            $event = [
                'source'        => config("{$this->configBase}.parser.name"),
                'ip'            => $report['ip'],
                'domain'        => $report['Domain'],
                'uri'           => $report['uri'],
                'class'         => config("{$this->configBase}.feeds.{$this->feedName}.class"),
                'type'          => config("{$this->configBase}.feeds.{$this->feedName}.type"),
                'timestamp'     => strtotime($report['Date']),
                'information'   => json_encode($report),
            ];

            $events[] = $event;
        }

        return $this->success($events);
    }
}
