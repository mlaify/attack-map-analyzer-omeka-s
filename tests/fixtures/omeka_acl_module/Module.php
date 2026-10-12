<?php

namespace Gallery;

use Gallery\Controller\FeedController;
use Laminas\EventManager\SharedEventManagerInterface;
use Laminas\Mvc\MvcEvent;
use Omeka\Module\AbstractModule;
use Omeka\Permissions\Acl;

class Module extends AbstractModule
{
    public function getConfig()
    {
        return include __DIR__ . '/config/module.config.php';
    }

    public function onBootstrap(MvcEvent $event)
    {
        parent::onBootstrap($event);
        $acl = $this->getServiceLocator()->get('Omeka\Acl');
        // Public site pages and the feed's index action only.
        $acl->allow(null, ['Gallery\Controller\Site\Index']);
        $acl->allow(null, [FeedController::class], ['index']);
        // Self-registered Guest users: effectively public.
        $acl->allow('guest', Controller\GuestController::class);
        // Editors only.
        $acl->allow(Acl::ROLE_EDITOR, [Controller\UploadController::class]);
        // Conditional: depends on an assertion at runtime.
        $acl->allow(null, Controller\VoteController::class, null, new Permissions\VotingOpenAssertion);
        // Public, except for `index`.
        $acl->allow(null, Controller\ClosedController::class);
        $acl->deny(null, Controller\ClosedController::class, 'index');
    }

    public function attachListeners(SharedEventManagerInterface $sharedEventManager)
    {
        // Not an ACL call: a different `allow` method.
        $sharedEventManager->attach('*', 'view.layout', [$this, 'allow']);
    }
}
