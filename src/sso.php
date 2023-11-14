<?php

namespace MiniOrange;

use App\Enums\UserType;
use App\Models\CompanyManager;
use App\Models\EnterpriseUser;
use App\Services\SubscriptionService;
use GPBMetadata\Google\Api\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use MiniOrange\Classes\Actions\ProcessResponseAction;
use MiniOrange\Classes\Actions\ProcessUserAction;
use MiniOrange\Classes\Actions\ReadResponseAction;
use MiniOrange\Classes\Actions\TestResultActions;
use MiniOrange\Helper\Constants;
use MiniOrange\Helper\Messages;
use MiniOrange\Helper\Utilities;
use MiniOrange\Helper\PluginSettings;
use MiniOrange\Classes\Actions\AuthFacadeController;
use MiniOrange\Helper\Lib\AESEncryption;
use Illuminate\Support\Facades\Session;
use App\Models\User;
use App\Models\Company;

final class SSO
{
    public function __construct()
    {
        $pluginSettings = PluginSettings::getPluginSettings();
        if (array_key_exists('SAMLResponse', $_REQUEST) && !empty($_REQUEST['SAMLResponse'])) {
            try {
                $relayStateUrl = array_key_exists('RelayState', $_REQUEST) ? $_REQUEST['RelayState'] : '/';
                $samlResponseObj = ReadResponseAction::execute(); // read the samlResponse from IDP
                $responseAction = new ProcessResponseAction($samlResponseObj);
                $responseAction->execute();
                $ssoemail = current(current($samlResponseObj->getAssertions())->getNameId());
                $attrs = current($samlResponseObj->getAssertions())->getAttributes();
                $attrs['NameID'] = array(
                    "0" => $ssoemail
                );

                // Get COOKIE From Login.php File
                $url = $_COOKIE['sso-url'] ?? null;
                $domain = $_COOKIE['sso-domain'] ?? null;
                $type = $_COOKIE['sso-type'] ?? 'candidate';

                //TODO: create or find user
                $user = User::where('email', $ssoemail)->first();
                if(blank($user)) {
                    $company = Company::where('custom_domain', $domain)->first();

                    $user = $this->createUser([
                        'email' => $ssoemail,
                        'type' => $type,
                        'company_id' => data_get($company, 'id')
                    ]);
                }

                $token = $user->createToken(User::USER_ACCESS_TOKEN)->accessToken;

                $redirectUrl = $type === 'admin' ? 'admin/login' : 'candidate/login';

                $sessionIndex = current($samlResponseObj->getAssertions())->getSessionIndex();

                if (strcasecmp($relayStateUrl, Constants::TEST_RELAYSTATE) == 0) {
                    (new TestResultActions($attrs))->execute(); // show test results
                } else {
                    (new ProcessUserAction($attrs, $relayStateUrl, $sessionIndex))->execute(); // process user action
                    session_start();
                    $_SESSION['email'] = $attrs['NameID'];
                    $_SESSION['username'] = $attrs['NameID'];
                    $encrypted_mail = urlencode(AESEncryption::encrypt_data($_SESSION['email'][0], "M12K19FV"));
                    $encrypted_name = urlencode(AESEncryption::encrypt_data($_SESSION['username'][0], "M12K19FV"));

                    $params = "token=$token&sso=1";
                    if($url) {
                        $params .= "&url=$url";
                    }

                    header("Location: $redirectUrl?$params");
                    exit();
                }
            } catch (\Exception $e) {
                if (strcasecmp($relayStateUrl, Constants::TEST_RELAYSTATE) === 0)
                    (new TestResultActions(array(), $e))->execute();
                else
                    Utilities::showErrorMessage($e->getMessage());
            }
        } else {
            Utilities::showErrorMessage(Messages::MISSING_SAML_RESPONSE);
        }
    }

    public function createUser($data) {
        try {
            $firstName = data_get($data, 'first_name');
            $lastName = data_get($data, 'last_name');
            $email = data_get($data, 'email');
            $password = data_get($data, 'password', 12345678);

            $type = data_get($data, 'type');
            $companyId = data_get($data, 'company_id');

            $userData = [
                'email' => $email,
                'password' => Hash::make($password),
                'type' => 'User',
                'status' => 1,
                'first_name' => $firstName,
                'last_name' => $lastName,
                'name' => $firstName." ".$lastName,
                'email_verified_at' => now()
            ];

            $userData['type'] = $type === 'admin' ? UserType::EMPLOYER : UserType::CANDIDATE;

            $user = User::create($userData);

            app(SubscriptionService::class)->subscribeToFreePackage($user);

            $enterpriseUser = EnterpriseUser::query()
                ->where('user_id', $user->id)
                ->where('company_id', $companyId)
                ->first();

            if(blank($enterpriseUser)) {
                $enterpriseUser = new EnterpriseUser();
                $enterpriseUser->user_id = $user->id;
                $enterpriseUser->company_id = $companyId;
                $enterpriseUser->password = bcrypt($password);
                $enterpriseUser->save();
            }

            return $user;
        } catch (Exception $e) {
            Log::error($e);
        }
    }
}

new SSO();