<?php

return [
    'router' => [
        'routes' => [
            'custom-admin' => [
                'type' => 'Literal',
                'options' => [
                    'route' => '/admin/custom-module',
                    'defaults' => [
                        'controller' => Application\Controller\AdminController::class,
                    ],
                ],
            ],
        ],
    ],
    'service_manager' => [
        'factories' => [
            CustomModule\Service\WebhookService::class => CustomModule\Service\WebhookFactory::class,
        ],
    ],
];
