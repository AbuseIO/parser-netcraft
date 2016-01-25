<?php

return [
    'parser' => [
        'name'          => 'Netcraft',
        'enabled'       => true,
        'report_file'   => '/report.txt/i',
        'sender_map'    => [
            '/takedown-response.*@netcraft.com/',
        ],
        'body_map'      => [
            //
        ],
        'aliases'       => [
        ],
    ],

    'feeds' => [
        'phishing' => [
            'class'     => 'PHISING_WEBSITE',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'Report-Type',
                'Category',
                'Source',
                'Date',
                'Domain',
                'Ip',
            ],
        ],

        'malware-attack' => [
            'class'     => 'COMPROMISED_WEBSITE',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'Report-Type',
                'Category',
                'Source',
                'Date',
                'Download-Link',
                'Ip',
            ],
        ],
    ],
];
