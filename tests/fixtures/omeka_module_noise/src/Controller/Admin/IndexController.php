<?php

namespace Harvester\Controller\Admin;

use Laminas\Mvc\Controller\AbstractActionController;

class IndexController extends AbstractActionController
{
    public function indexAction()
    {
        // Non-secret connection settings.
        $host = getenv('DB_HOST');
        $endpoint = $_ENV['API_URL'];
        $prefix = getenv('cache_key_prefix');
        // Secret-shaped names.
        $password = getenv('DB_PASSWORD');
        $token = $_ENV['API_TOKEN'];

        return $this->redirect()->toRoute('admin/harvester', ['action' => 'browse']);
    }
}
