<?php

namespace Application\Controller;

use Omeka\Connection;

class AdminController
{
    public function __construct(private Connection $connection)
    {
    }
}
