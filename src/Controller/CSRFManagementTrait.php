<?php

namespace Skyline\CMS\Security\Controller;

use ArrayAccess;
use Skyline\CMS\Security\Exception\CSRFMissmatchException;
use Skyline\Render\Model\ArrayModel;
use Skyline\Render\Model\ModelInterface;
use Skyline\Security\CSRF\CSRFToken;
use Skyline\Security\CSRF\CSRFTokenManager;
use Skyline\Security\CSRF\InputCSRFToken;
use Symfony\Component\HttpFoundation\Request;
use TASoft\Service\ServiceManager;

/**
 * Trait CSRFManagementTrait
 * @package Skyline\CMS\Security\Controller
 * @method getModel()
 * @property-read $modelClassName
 */
trait CSRFManagementTrait
{
    public function getCSRFManager(): CSRFTokenManager {
        return ServiceManager::generalServiceManager()->get("CSRFManager");
    }

    /**
     * Checks, if a csrf token was transmitted.
     * If not, this method returns false.
     * If there is a token but it does not match, throws an exception, otherwise return true.
     *
     * @param string $name
     * @param Request|NULL $request
     * @return bool
     * @throws CSRFMissmatchException
     */
    public function verifyCSRF(string $name = 'skyline-csrf-token', Request $request = NULL): bool {
        if(!$request)
            $request = ServiceManager::generalServiceManager()->get("request");

        if($request) {
            if($request->request->has($name)) {
                $tk = $request->request->get($name);
                if(!$this->getCSRFManager()->isTokenValid($token = new CSRFToken($name, $tk))) {
                    $e = new CSRFMissmatchException("Csrf token missmatch", 403);
                    $e->setToken($token);
                    throw $e;
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Makes a HTML token that can be printed directly.
     *
     * @param string|CSRFToken $token
     * @return InputCSRFToken
     */
    public function buildHTMLCsrfToken($token = 'skyline-csrf-token') {
        if(!($token instanceof CSRFToken))
            $token = $this->getCSRFManager()->getToken( $token );

        return new InputCSRFToken(
            $token->getId(),
            $token->getValue()
        );
    }


    /**
     * Build a CSRF token and adds it to an existing model or creates a new model
     *
     * @param string $tokenID
     * @param ArrayAccess|ArrayModel|NULL $model
     * @param string $fieldName
     * @return ArrayAccess|ArrayModel|ModelInterface|null
     * @see AbstractActionController::$modelClassName
     */
    public function buildCSRFModel(string $tokenID = 'skyline-csrf-token', $model = NULL, string $fieldName = 'CSRF') {
        if(!$model) {
            if(method_exists($this, 'getModel'))
                $model = $this->getModel();
            elseif(property_exists($this, 'modelClassName'))
                $model = new $this->modelClassName;
            else
                return NULL;
        }

        $csrf = $this->getCSRFManager();
        $model[ $fieldName ] = $csrf->getToken( $tokenID );

        return $model;
    }
}