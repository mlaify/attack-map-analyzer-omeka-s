<?php

namespace Omeka;

class Module
{
    public function getConfig()
    {
        return array_merge(include __DIR__ . '/config/module.config.php', include __DIR__ . '/config/routes.config.php');
    }
}
