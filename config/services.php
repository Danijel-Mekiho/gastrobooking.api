<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Stripe, Mailgun, Mandrill, and others. This file provides a sane
    | default location for this type of information, allowing packages
    | to have a conventional place to find your various credentials.
    |
    */

    'mailgun' => [
        'domain' => env('MAILGUN_DOMAIN'),
        'secret' => env('MAILGUN_SECRET'),
    ],

    'ses' => [
        'key' => env('SES_KEY'),
        'secret' => env('SES_SECRET'),
        'region' => 'us-east-1',
    ],

    'sparkpost' => [
        'secret' => env('SPARKPOST_SECRET'),
    ],

    'stripe' => [
        'model' => App\User::class,
        'key' => env('STRIPE_KEY'),
        'secret' => env('STRIPE_SECRET'),
    ],
    
    'twitter' => [
        'client_id' => 'iN0pafOooFLqDXeYDVRhXxtlB',
        'client_secret' => '6nC6onx0ZMavJhdM7z97GR63rrma9y7Kuzy5amzCM4CTEuEm01',
        'redirect' => 'http://'. $_SERVER['SERVER_NAME']. '/api/auth/twitter/callback',
    ],
    'facebook' => [
        'client_id' => '124305421485015',
        'client_secret' => 'bed5b254d886c636e049732cb815a1d9',
        'redirect' => 'http://'. $_SERVER['SERVER_NAME']. '/api/auth/facebook/callback',
    ],
];
