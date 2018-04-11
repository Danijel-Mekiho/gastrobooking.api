<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use Auth;
use Socialite;
use App\Http\Requests;
use App\User;
use App\Entities\Client;
use Illuminate\Support\Facades\Redirect;

class SocialAuthController extends Controller
{
 	public function redirectToProvider(Request $request, $social_type)
    {
        if( $social_type == 'facebook') {
            return Socialite::driver('facebook')->fields([
                'name', 'email', 'gender', 'birthday','location'
            ])->scopes([
                'email', 'user_birthday','user_location'
            ])->redirect();
        }
        return Socialite::driver($social_type)->redirect();
    }

    public function handleProviderCallback(Request $request, $social_type)
    {

        try {
            if( $social_type == 'facebook') {
                $user = Socialite::driver('facebook')->fields([
                    'name', 'email', 'gender', 'birthday','location'
                ])->user();
            } else
                $user = Socialite::driver($social_type)->user();
        } catch (Exception $e) {
            return redirect('/api/auth/'. $social_type);
        }
        $authUser = $this->findOrCreateUser($user, $social_type);
        $email = $authUser->email;
        $url = config('domain.redirect_domain_ui').'#/app/social_login/'. $email;
        return Redirect::to($url);
    }
 
    /**
     * Return user if exists; create and return if doesn't
     *
     * @param $socialUser
     * @return User
     */
    private function findOrCreateUser($socialUser, $social_type)
    {
        $authUser = User::where('email', $socialUser->email)->first();
        $social_con_at = time();
        if ($authUser){
            $authUser->social_con_at = $social_con_at;
            $authUser->social_password = bcrypt($social_con_at);
            $authUser->save();
            return $authUser;
        }
        
 	    $user = new User;
        $user->name = $socialUser->name;
        $user->email = $socialUser->email;
        $user->social_password = bcrypt($social_con_at);
        $user->social_con_at = $social_con_at;
        $user->profile_type = 'client';
        $user->save();
        $lang = "";
        $location = "";
        if( $social_type == 'facebook') {
            if( array_key_exists('location', $socialUser->user) && array_key_exists('name', $socialUser->user['location']))
                $location = $socialUser->user['location']['name'];
        } else if(  $social_type == 'twitter' ) {
            $lang = strtoupper($socialUser->user['lang']);
            $location = $socialUser->user['location'];
        }    
        $client = new Client;
        $client->ID_user = $user->id;
        $client->email_update = '1';
        //$client->lang = $lang;
        $client->location = $location;
        $client->save();
        return $user;
    }
}
