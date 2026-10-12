<?php
namespace Omeka\Mvc;

use Laminas\Mvc\MvcEvent;

class MvcListeners
{
    public function authenticateApiKey(MvcEvent $event)
    {
        if (!$event->getRouteMatch()->getParam('__KEYAUTH__')) {
            return;
        }
        $identity = $event->getRequest()->getQuery('key_identity');
        $credential = $event->getRequest()->getQuery('key_credential');
        // A message that mentions "key_identity" is not a reader.
        $note = 'Pass "key_identity" and "key_credential" as query parameters.';
    }
}
