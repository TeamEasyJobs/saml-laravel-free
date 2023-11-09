<?php

namespace MiniOrange;

use MiniOrange\Classes\Actions\SendAuthnRequest;
use MiniOrange\Helper\Utilities;

final class Login
{

    public function __construct()
    {
        try {
            setcookie('sso-type', request()->get('type', 'candidate'), time() + 60, '/');

            SendAuthnRequest::execute();
        } catch (\Exception $e) {
            Utilities::showErrorMessage($e->getMessage());
        }
    }
}

new Login();