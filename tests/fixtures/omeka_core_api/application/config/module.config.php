<?php

namespace Omeka;

return [
    'controllers' => [
        'invokables' => [
            'Omeka\Controller\Index' => Controller\IndexController::class,
            'Omeka\Controller\Site\Index' => Controller\Site\IndexController::class,
            'Omeka\Controller\Site\Item' => Controller\Site\ItemController::class,
            'Omeka\Controller\Admin\Item' => Controller\Admin\ItemController::class,
        ],
        'factories' => [
            'Omeka\Controller\Api' => Service\Controller\ApiControllerFactory::class,
            'Omeka\Controller\Install' => Service\Controller\InstallControllerFactory::class,
        ],
    ],
];
