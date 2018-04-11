<?php

namespace App\Http\Controllers;

use Dingo\Api\Routing\Helpers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Lang;

class TranslateController extends Controller
{
    public function index(Request $request){
        app()->setLocale($request->input('lang', 'en'));

        return response()->json(
            Lang::get('main')
        );
    }
}
