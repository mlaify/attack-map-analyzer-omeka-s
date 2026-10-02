<?php

namespace Harvester;

return [
    'router' => [
        'routes' => [
            'admin' => [
                'child_routes' => [
                    'harvester' => [
                        'type' => \Laminas\Router\Http\Segment::class,
                        'options' => [
                            'route' => '/harvester[/:action]',
                            'defaults' => [
                                '__NAMESPACE__' => 'Harvester\Controller\Admin',
                                'controller' => Controller\Admin\IndexController::class,
                                'action' => 'index',
                            ],
                        ],
                        'child_routes' => [
                            'job' => [
                                'type' => \Laminas\Router\Http\Segment::class,
                                'options' => [
                                    'route' => '[/:id]',
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ],
    ],
    // Admin navigation names routes; these are not URL paths.
    'navigation' => [
        'AdminModule' => [
            [
                'label' => 'Harvester',
                'route' => 'admin/harvester',
                'resource' => Controller\Admin\IndexController::class,
                'pages' => [
                    ['label' => 'Past jobs', 'route' => 'admin/harvester/job', 'visible' => false],
                ],
            ],
        ],
    ],
];
