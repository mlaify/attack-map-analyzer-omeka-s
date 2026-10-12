<?php

namespace Gallery;

return [
    'controllers' => [
        'invokables' => [
            // Short name: the `site` child route resolves it via __NAMESPACE__.
            'Gallery\Controller\Site\Index' => Controller\Site\IndexController::class,
            Controller\Admin\IndexController::class => Controller\Admin\IndexController::class,
            Controller\FeedController::class => Controller\FeedController::class,
            Controller\UploadController::class => Controller\UploadController::class,
            Controller\VoteController::class => Controller\VoteController::class,
            Controller\GuestController::class => Controller\GuestController::class,
            Controller\ClosedController::class => Controller\ClosedController::class,
            Controller\PrivateController::class => Controller\PrivateController::class,
        ],
    ],
    'router' => [
        'routes' => [
            // Children of Omeka core's `site` and `admin` routes, which this
            // module repo doesn't define.
            'site' => [
                'child_routes' => [
                    'gallery' => [
                        'type' => \Laminas\Router\Http\Segment::class,
                        'options' => [
                            'route' => '/gallery[/:action]',
                            'defaults' => [
                                '__NAMESPACE__' => 'Gallery\Controller\Site',
                                'controller' => 'Index',
                                'action' => 'browse',
                            ],
                        ],
                    ],
                ],
            ],
            'admin' => [
                'child_routes' => [
                    'gallery' => [
                        'type' => \Laminas\Router\Http\Segment::class,
                        'options' => [
                            'route' => '/gallery[/:action]',
                            'defaults' => [
                                'controller' => Controller\Admin\IndexController::class,
                                'action' => 'browse',
                            ],
                        ],
                    ],
                ],
            ],
            'gallery-feed' => [
                'type' => \Laminas\Router\Http\Literal::class,
                'options' => [
                    'route' => '/gallery-feed',
                    'defaults' => ['controller' => Controller\FeedController::class, 'action' => 'index'],
                ],
                'may_terminate' => true,
                'child_routes' => [
                    'full' => [
                        'type' => \Laminas\Router\Http\Literal::class,
                        'options' => ['route' => '/full', 'defaults' => ['action' => 'full']],
                    ],
                ],
            ],
            'gallery-upload' => [
                'type' => \Laminas\Router\Http\Literal::class,
                'options' => [
                    'route' => '/gallery-upload',
                    'defaults' => ['controller' => Controller\UploadController::class, 'action' => 'upload'],
                ],
                'child_routes' => [
                    'post' => [
                        'type' => \Laminas\Router\Http\Method::class,
                        'options' => ['verb' => 'post'],
                    ],
                ],
            ],
            'gallery-vote' => [
                'type' => \Laminas\Router\Http\Literal::class,
                'options' => [
                    'route' => '/gallery-vote',
                    'defaults' => ['controller' => Controller\VoteController::class, 'action' => 'vote'],
                ],
            ],
            'gallery-guest' => [
                'type' => \Laminas\Router\Http\Literal::class,
                'options' => [
                    'route' => '/gallery-guest',
                    'defaults' => ['controller' => Controller\GuestController::class, 'action' => 'index'],
                ],
            ],
            'gallery-closed' => [
                'type' => \Laminas\Router\Http\Segment::class,
                'options' => [
                    'route' => '/gallery-closed[/:action]',
                    'defaults' => ['controller' => Controller\ClosedController::class, 'action' => 'index'],
                ],
            ],
            'gallery-private' => [
                'type' => \Laminas\Router\Http\Literal::class,
                'options' => [
                    'route' => '/gallery-private',
                    'defaults' => ['controller' => Controller\PrivateController::class, 'action' => 'index'],
                ],
            ],
        ],
    ],
];
