<?php
namespace Omeka\Service;

use Omeka\Permissions\Acl;

class AclFactory
{
    public function __invoke($serviceLocator, $requestedName, ?array $options = null)
    {
        $acl = new Acl;
        $status = $serviceLocator->get('Omeka\Status');
        if (!$status->isInstalled()) {
            // Installation: everything is allowed (ignored by the analyzer).
            $acl->allow();
        } else {
            $this->addRules($acl);
        }
        return $acl;
    }

    protected function addRules(Acl $acl)
    {
        $acl->allow(
            null,
            [
                'Omeka\Controller\Site\Index',
                'Omeka\Controller\Site\Item',
            ]
        );
        $acl->allow(
            null,
            [
                'Omeka\Controller\Api',
                'Omeka\Controller\Index',
            ]
        );
        $acl->allow(
            'researcher',
            'Omeka\Controller\Admin\Item',
            ['index', 'browse', 'show']
        );
        $acl->allow('global_admin');
    }
}
