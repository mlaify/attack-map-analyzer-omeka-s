<?php

return [
    'router' => [
        'routes' => [
            'admin' => [
                'type' => 'Literal',
                'options' => [
                    'route' => '/admin',
                    'defaults' => [
                        'controller' => Application\Controller\AdminController::class,
                    ],
                ],
            ],
            'api' => [
                'type' => 'Literal',
                'options' => [
                    'route' => '/api',
                    'defaults' => [
                        'controller' => Application\Controller\ApiController::class,
                    ],
                ],
            ],
            'site' => [
                'type' => 'Segment',
                'options' => [
                    'route' => '/s/:site-slug',
                    'defaults' => [
                        'controller' => Application\Controller\SiteController::class,
                    ],
                ],
            ],
        ],
    ],
    'controllers' => [
        'factories' => [
            Application\Controller\AdminController::class => Application\Service\AdminFactory::class,
        ],
    ],
    'service_manager' => [
        'factories' => [
            Omeka\Connection::class => Application\Service\ConnectionFactory::class,
        ],
    ],
    'navigation' => [
        'AdminNavigation' => [],
    ],
];
