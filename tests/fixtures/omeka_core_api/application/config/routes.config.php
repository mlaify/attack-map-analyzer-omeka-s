<?php
return [
    'router' => [
        'routes' => [
            'site' => [
                'type' => \Laminas\Router\Http\Segment::class,
                'options' => [
                    'route' => '/s/:site-slug',
                    'defaults' => [
                        '__NAMESPACE__' => 'Omeka\Controller\Site',
                        '__SITE__' => true,
                        'controller' => 'Index',
                        'action' => 'index',
                    ],
                ],
                'may_terminate' => true,
                'child_routes' => [
                    'resource' => [
                        'type' => \Laminas\Router\Http\Segment::class,
                        'options' => [
                            'route' => '/:controller[/:action]',
                            'defaults' => ['action' => 'browse'],
                        ],
                    ],
                ],
            ],
            'admin' => [
                'type' => \Laminas\Router\Http\Literal::class,
                'options' => [
                    'route' => '/admin',
                    'defaults' => [
                        '__NAMESPACE__' => 'Omeka\Controller\Admin',
                        '__ADMIN__' => true,
                        'controller' => 'Index',
                        'action' => 'browse',
                    ],
                ],
                'may_terminate' => true,
                'child_routes' => [
                    'default' => [
                        'type' => \Laminas\Router\Http\Segment::class,
                        'options' => ['route' => '/:controller[/:action]'],
                    ],
                ],
            ],
            'api' => [
                'type' => \Laminas\Router\Http\Literal::class,
                'options' => [
                    'route' => '/api',
                    'defaults' => [
                        '__API__' => true,
                        '__KEYAUTH__' => true,
                        'controller' => 'Omeka\Controller\Api',
                    ],
                ],
                'may_terminate' => true,
                'child_routes' => [
                    'default' => [
                        'type' => \Laminas\Router\Http\Segment::class,
                        'options' => ['route' => '[/:resource[/:id]]'],
                    ],
                ],
            ],
            'install' => [
                'type' => \Laminas\Router\Http\Regex::class,
                'options' => [
                    'regex' => '/install(/.*)?',
                    'spec' => '/install',
                    'defaults' => ['controller' => 'Omeka\Controller\Install', 'action' => 'index'],
                ],
            ],
        ],
    ],
];
