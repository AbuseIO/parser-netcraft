<?php

return [
    'parser' => [
        'name'          => 'Netcraft',
        'enabled'       => true,
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
            'class'     => 'Phishing website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Report-Type',
                'Category',
                'Source',
                'Date',
                'Domain',
            ],
        ],

        'malware-attack' => [
            'class'     => 'Compromised website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Report-Type',
                'Category',
                'Source',
                'Date',
                'Download-Link',
            ],
        ],
    ],
];
