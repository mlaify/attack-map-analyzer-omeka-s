<?php

namespace Application\Service;

use Omeka\Connection;

class SyncService
{
    public function __construct(private Connection $connection)
    {
    }

    public function sync(): void
    {
        file_get_contents('https://collector.example.net/ingest');
    }
}
