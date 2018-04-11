<?php
/**
 * Created by PhpStorm.
 * User: tOm_HydRa
 * Date: 9/10/16
 * Time: 12:06 PM
 */

namespace App\Repositories;


use App\Entities\Client;
use App\Entities\ClientGroup;
use App\Entities\Ingredient;
use App\Entities\MealRequest;
use App\Entities\RequestMenu;
use App\Entities\Order;
use App\Entities\OrderDetail;
use App\Entities\RequestIngredient;
use App\Entities\RequestParam;
use App\Entities\RestaurantOpen;
use App\Entities\Restaurant;
use App\Entities\RestaurantOrderNumber;
use App\Entities\SyncServOwn;
use Illuminate\Pagination\LengthAwarePaginator;
use App\Entities\Setting;
use App\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Mail;
use Carbon\Carbon;
use DB;

class ClientRepository
{
    protected $userRepository;
    protected $clientGroupRepository;
    
    public function __construct(UserRepository $userRepository, ClientGroupRepository $clientGroupRepository)
    {
        $this->userRepository = $userRepository;
        $this->clientGroupRepository = $clientGroupRepository;
    }

    public function item($clientId){
        return Client::find($clientId);
    }

    public function store($request)
    {
        $user_exists = $this->userRepository->userExists($request->user);
        if ($user_exists){
            return false;
        }
        $user = $this->saveUser($request->user);
        $request_client = $request->client;
        $client = new Client();
        $client->ID_user = $user->id;
        $client->email_new = $request_client["email_new"] ? 1 : 0;
        $client->email_update = $request_client["email_update"] ? 1 : 0;
        $client->email_restaurant_update = $request_client["email_restaurant_update"] ? 1 : 0;
        $client->lang = $request_client["lang"] ? $request_client["lang"] : 'ENG';
        $client->save();
        return $user;
    }
    
    public function saveUser($user){
        return $this->userRepository->store($user, "client");
    }

    public function getUserName() {
        $user = app('Dingo\Api\Auth\Auth')->user();
        $currentUserName = Client::where("ID", $user->client->ID)->first()->user->name;
        return $currentUserName;
    }

    public function all($request)
    {
        $user = app('Dingo\Api\Auth\Auth')->user();
        $friends = ClientGroup::where("ID_client", $user->client->ID)->whereIn("approved", ["Y", "R", "N"]);
        $friend_ids = $friends->pluck("ID_grouped_client");
        $friends2 = ClientGroup::where("ID_grouped_client", $user->client->ID)->whereIn("approved", ["Y", "R"]);
        $friend_ids2 = $friends2->pluck("ID_client");
        return Client::whereNotIn("ID", $friend_ids)->where('ID','<>',$user->client->ID)->searchClient($request)->get();
    }



    public function getRestaurantOpeningHours($ID){

        $getOpeningHours = RestaurantOpen::where("ID_restaurant", $ID)->get(['date', 'm_starting_time', 'm_ending_time', 'a_starting_time', 'a_ending_time']);

        $openingHours = array();
        foreach ($getOpeningHours as $value) {
            $openingHours[$value->date] = array('m_starting_time' => $value->m_starting_time,'m_ending_time' => $value->m_ending_time,'a_starting_time' => $value->a_starting_time,'a_ending_time' => $value->a_ending_time);
        }
        return $openingHours;
    }


    public function getIngredients($currentLanguage)
    {
        return Ingredient::where([["lang", $currentLanguage], ["public", 1]])->groupBy('name')->get();
    }

    public function currentUserCurrency()
    {
        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        if ( isset($client->lang) && !empty($client->lang) ) {
            $langSett = $client->lang;
        }
        else{
            $langSett = 'CZE';
        }
        $setting = Setting::where('lang', '=', $langSett)->first();
        $currency = $setting->currency_short;
        return $currency;
    }

    public function countUnreadRequest(){
        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        $getClientsID = Order::where('ID_client', '=', $client->ID)->pluck("ID");

        $countNewRequests = MealRequest::where([ ['unread', '=', 'C'], ['status', '=', 'S'] ] )->whereIn('ID_orders', $getClientsID)->get()->count();

        $countConfirmRequests = MealRequest::where([ ['unread', '=', 'C'], ['status', '=', 'A'] ] )->whereIn('ID_orders', $getClientsID)->get()->count();

        $countCancelRequests = MealRequest::where([ ['unread', '=', 'C'], ['status', '=', 'E'] ] )->whereIn('ID_orders', $getClientsID)->get()->count();

        $count = array('new_unread' => $countNewRequests,'confirm_unread' => $countConfirmRequests,'cancel_unread' =>$countCancelRequests);
        
        return $count;
    }


    public function countMissingBooking(){

        DB::enableQueryLog();

        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        $all_order_details = [];

        $orders = Order::with(['request','request_order_detail', 'request_order_detail.requestMenu', 'request_order_detail.requestParam'])
        ->where([['ID_client',$client->ID]])->get();

        foreach ($orders as $okey => $order) {
            if(isset($order->request) && ($order->request->status == 'S' || $order->request->status == 'A'))
            {
                $order_details_ids = [];

                foreach ($order->request_order_detail as $key => $orders_detail) {
                    $order_details_ids[] = $orders_detail->ID;
                    $request_params = RequestParam::with(["order_detail","order_detail.order","order_detail.requestMenu"])
                    ->whereBetween('request_from', array($orders_detail->requestParam->request_from, $orders_detail->requestParam->request_to))
                    ->orWhereBetween('request_to', array($orders_detail->requestParam->request_from, $orders_detail->requestParam->request_to))
                    ->orWhere([["request_from",">=",$orders_detail->requestParam->request_from],["request_to","<=",$orders_detail->requestParam->request_to]])
                    ->orWhere("request_from","=","00:00:00")
                    ->orWhere("request_to","=","00:00:00")
                    ->whereHas('order_detail.requestMenu', function ($query) use($orders_detail){
                        if(!empty($orders_detail->requestMenu->confirmed_name))
                        $query->where('name', '=', $orders_detail->requestMenu->confirmed_name)->orWhere('confirmed_name', '=', $orders_detail->requestMenu->confirmed_name);
                        else
                        $query->where('name', '=', $orders_detail->requestMenu->name)->orWhere('confirmed_name', '=', $orders_detail->requestMenu->name);
                    })
                    ->whereHas('order_detail.order', function ($query) use($order){
                        $query->where('ID_restaurant', '=', $order->ID_restaurant);
                    })->get();

                    $count = 0; 
                    $detail_serve_at = date('Y-m-d', strtotime( $orders_detail->serve_at ) );
                    foreach ($request_params as $key => $request_param) {
                        $request_param_serve_at = date('Y-m-d', strtotime( $request_param->order_detail->serve_at ) );
                        if(isset($request_param->order_detail)
                         && isset($request_param->order_detail->order)
                          && isset($request_param->order_detail->requestMenu) 
                          && isset($request_param->order_detail->order->ID_restaurant) 
                          && ($request_param->order_detail->order->ID_restaurant==$order->ID_restaurant) 
                          && ($detail_serve_at == $request_param_serve_at)
                          && ((empty($request_param->order_detail->requestMenu->confirmed_name) || ($request_param->order_detail->requestMenu->confirmed_name == (empty($orders_detail->requestMenu->confirmed_name)?$orders_detail->requestMenu->name:$orders_detail->requestMenu->confirmed_name))) 

                          && (!empty($request_param->order_detail->requestMenu->confirmed_name) || $request_param->order_detail->requestMenu->name == (empty($orders_detail->requestMenu->confirmed_name)?$orders_detail->requestMenu->name:$orders_detail->requestMenu->confirmed_name)))){
                                $serve_at = date('H:i', strtotime($request_param->order_detail->serve_at) );
                                $next_serve_at = date('H:i', strtotime($request_param->order_detail->serve_at.'+1 hour') );
                                $from_serve_at = date('H:i', strtotime($request_param->request_from) );
                                $to_serve_at = date('H:i', strtotime($request_param->request_to) );
                                if ( ($orders_detail->requestParam->request_from == '00:00:00' || $orders_detail->requestParam->request_from == ''
                                    || $orders_detail->requestParam->request_to == '00:00:00' || $orders_detail->requestParam->request_to == '')
                                    && ( (($from_serve_at >= $serve_at) && ($to_serve_at <= $next_serve_at)) || ($request_param->order_detail->ID ==  $orders_detail->ID)) ) {
                                        $count++;
                                }
                                else{
                                    $x_number = $request_param->order_detail->x_number;
                                    $count = $count + $x_number;
                                }
                        }
                    }
                    $all_order_details[$orders_detail->ID] = $count;
                }
            }
        }
        return $all_order_details;
    }


    public function getRequests($status)
    {      

        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        $getClientsID = Order::where('ID_client', '=', $client->ID)->pluck("ID");

        $getMealRequests = MealRequest::with(['orders','orders.request_orders_detail','orders.request_order_detail','orders.request_order_detail.requestParam','orders.request_order_detail.requestMenu','orders.request_order_detail.requestMenu.requestIngredient','orders.request_order_detail.requestMenu.requestIngredient.ingredient','orders.request_order_detail.requestMenu.requestIngredient.duplicate_of_ingredient','orders.request_order_detail.requestMenu.requestIngredient.duplicate_of_ingredient.ingredient' ])->whereIn('ID_orders', $getClientsID);

        if ( $status == 'N' ) {
            $getMealRequests = $getMealRequests->where('status', '=', 'N')->orWhere('status', '=', 'S');
        }
        else if( $status == 'C' ){
            $getMealRequests = $getMealRequests->where('status', '=', 'A');
        }
        else if( $status == 'CA' ){
            $getMealRequests = $getMealRequests->where('status', '=', 'E')->orWhere('status', '=', 'C');
        }

        $getMealRequests = $getMealRequests->get();

        $before = collect();
        $after = collect();
        if (count($getMealRequests)){
            foreach ($getMealRequests as $getMealRequest) {
                $order = $getMealRequest->orders;
                $orders_detail = $order->request_order_detail;
                $current_time = Carbon::now("Europe/Prague");
                if ( trim($client->ID) == trim($order->ID_client) ) {
                    foreach ($orders_detail as $order_detail) {
                        $serve_time = new Carbon($order_detail->serve_at);
                        $diffInMinutes = $this->getDiffInTimeCustom($serve_time, $current_time);
                        $order_detail->difference = $diffInMinutes;
                    }

                    $orders_detail = $orders_detail->sortBy("difference");
                    $filtered_order_detail = $orders_detail->first();
                    if ($filtered_order_detail){
                        $serve_at = new Carbon($filtered_order_detail->serve_at);
                        $diff = $this->getDiffInTimeCustom($serve_at, $current_time);
                        $getMealRequest->diff = $diff;
                        if ($diff >= 0){
                            $before->push($getMealRequest);
                        } else {
                            $after->push($getMealRequest);
                        }
                    }
                }
            }

            $before = $before->sortBy('diff');

            $after = $after->sortByDesc('diff');
            $merged = $before->merge($after);
            if (!count($merged)) {
                return "Meal Request Not Found";
            }

            $currentPage = LengthAwarePaginator::resolveCurrentPage();
            $pagedData = $merged->slice(($currentPage - 1) * 5, 5)->all();
            return new LengthAwarePaginator($pagedData, count($merged), 5);

        }
        return "Meal Request Not Found";
    }

    public function updateSyncServOwnTable($restaurantID, $updated = 0) {
        $data = SyncServOwn::where('ID_restaurant', $restaurantID)->first();
        if (!$data) {
            $data = new SyncServOwn();
            $data->ID_restaurant = $restaurantID;
        }

        if ($updated == 0) {
            $data->request_menu = Carbon::now();
            $data->request_ingredient = Carbon::now();
            $data->orders = Carbon::now();
            $data->orders_detail = Carbon::now();
            $data->client = Carbon::now();
            $data->user = Carbon::now();

            $client = app('Dingo\Api\Auth\Auth')->user()->client;
            $user = app('Dingo\Api\Auth\Auth')->user();

            $client->last_update = Carbon::now();
            $client->save();

            $user->last_update = Carbon::now();
            $user->save();
        } else {
            $data->request_menu = Carbon::now();
            $data->request_ingredient = Carbon::now();
            $data->orders = Carbon::now();
            $data->orders_detail = Carbon::now();
            $data->client = Carbon::now();
            $data->user = Carbon::now();
        }

        $data->save();

        return 1;
    }

    public function sendRequest($request) {
        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        $lang = $request->input('lang', '');

        /*..Save  Order ....*/
        $created_at = Carbon::now("Europe/Prague");
        $order = new Order();
        $order->ID_client = $client->ID;
        $order->status = 0;
        $order->comment = (($request->comment)) ? $request->comment : '';
        $order->ID_restaurant = (($request->new_restaurant_id)) ? $request->new_restaurant_id : null;
        $order->req_number = (($request->req_number)) ? $request->req_number : '';
        $order->persons = (($request->persons)) ? $request->persons : '';
        $order->created_at = $created_at->toDateTimeString();
        $order->save();
        $ID_order = $order->ID;
        if (!$ID_order) {
            return ['message' => "Error"];
        }

        /*...Save request_menu...*/
        $orders_detail_filtered = [];
        $request_menuID = array();
        if ($request->mealslist) {
            foreach ($request->mealslist as $value) {
                $request_menu = new RequestMenu();
                $request_menu_name = ((isset($value['request_menu_name']))) ? $value['request_menu_name'] : '';
                $lang = ((isset($value['lang']))) ? $value['lang'] : 'CZE';
                $request_menu->name = $request_menu_name;
                $request_menu->lang = $lang;
                $request_menu->save(['timestamps' => false]);
                $request_menuID = $request_menu->ID;
                if (!$request_menuID) {
                    return ['message' => "Error"];
                }
                $request_menu_filtered[] = $request_menu;

                $x_number = ((isset($value['x_number']))) ? $value['x_number'] : 0;
                $serve_at = ((isset($value['serve_at']))) ? $value['serve_at'] : '';
                $price = ((isset($value['price']))) ? $value['price'] : 0;
                $comment = ((isset($value['comment']))) ? $value['comment'] : '';
                $friend_id = ((isset($value['friend_id']))) ? $value['friend_id'] : $client->ID;
                $currency = ((isset($value['currency']))) ? $value['currency'] : 'Kč';
                if (isset($value['side_dish'])) {
                    if ($value['side_dish'] == 'Y') {
                        //$side_dish = (($order_detail->ID)) ? $order_detail->ID : 0;
                        $side_dish = 0;
                    }
                    else{
                        $side_dish = 0;
                    }
                }
                else{
                    $side_dish = 0;
                }

                $price = number_format($price*$x_number, 2);

                $order_detail = new OrderDetail();
                $order_detail->ID_orders = $ID_order;
                $order_detail->ID_client = $friend_id;
                $order_detail->ID_request_menu = $request_menu->ID;
                $order_detail->x_number = $x_number;
                $order_detail->serve_at = $serve_at;
                $order_detail->price = $price;
                $order_detail->currency = $currency;
                $order_detail->comment = $comment;
                $order_detail->side_dish = $side_dish;
                $order_detail->save();
                if (!$order_detail->ID) {
                    return ['message' => "Error"];
                }

                $orders_detail_filtered[] = $order_detail;
               

                /*....Save Ingredients.........*/
                $ingredientsDetails = array();
                if (isset($value['ingredientsDetails']) && !empty($value['ingredientsDetails'])) {
                    $value = $value['ingredientsDetails'];
                    $ingredientsDetails = array_merge($ingredientsDetails, $value);
                    $ingredientsDetails = collect($ingredientsDetails);
                    $ingredients = $ingredientsDetails->map(function ($request_menuid) use($request_menuID){
                        unset($request_menuid['name']);
                        $request_menuid['ID_request_menu'] = $request_menuID;
                        return $request_menuid;
                    });
                    RequestIngredient::insert($ingredients->toArray());
                }

            }
        }

        /*..Save  Restaurant ....*/
        $requests = new MealRequest();

        $requests->ID_restaurant = (($request->new_restaurant_id)) ? $request->new_restaurant_id : null;
        $requests->ID_orders = $ID_order;
        $requests->status = 'N';
        $requests->unread = 'R';
        $requests->new_restaurant = (($request->new_restaurant_name)) ? $request->new_restaurant_name : '';
        $requests->new_address = (($request->new_address)) ? $request->new_address : '';
        $requests->save(['timestamps' => false]);

        if ($request->new_restaurant_id) {
            $restaurantID = $request->new_restaurant_id;
            $restaurant = Restaurant::find($restaurantID);
            $new_restaurant = '';

            $this->updateSyncServOwnTable($request->new_restaurant_id);
        }
        else{
            $restaurant = '';
            $new_restaurant = array();
            $new_restaurant['name'] = (($request->new_restaurant_name)) ? $request->new_restaurant_name : '';
            $new_restaurant['address'] = (($request->new_address)) ? $request->new_address : '';
        }


        $sent = $this->sendEmailReminder('new', app('Dingo\Api\Auth\Auth')->user(), $order,$restaurant,
                $lang, $orders_detail_filtered, 'user', $new_restaurant, $request_menu_filtered);

        $sent_rest = $this->sendEmailReminder('new', app('Dingo\Api\Auth\Auth')->user(), $order, $restaurant,
            $restaurant->lang, $orders_detail_filtered, 'rest', $new_restaurant, $request_menu_filtered);

        $sent_sms = $this->sendSMSEmailReminder(
            'new_short',
            app('Dingo\Api\Auth\Auth')->user(),
            $order,
            $restaurant,
            'admin',
            $new_restaurant,
            $orders_detail_filtered,
            $request_menu_filtered,
            $restaurant->lang ?: 'cs'
        );

        if (!$requests->ID) {
            return ['message' => "Error"];
        }
        return ['message' => "Request send"];
    }


     public function sendSMSEmailReminder($type, User $user, Order $order, $restaurant, $to, $new_restaurant, $orders_detail_filtered, $request_menu_filtered, $lang)
    {
        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        if ( isset($client->lang) && !empty($client->lang) ) {
            $langSett = $client->lang;
        }
        else{
            $langSett = 'CZE';
        }

        $setting = Setting::where('lang', '=', $langSett)->first();
        $lang = Setting::where('lang', '=', $lang)->first()->short_name;
        app()->setLocale($lang);
        $currency = $setting->currency_short;

        $path = 'emails.requestMeal.request_'.$type;

        try {
            if ( isset($restaurant->SMS_phone) ) {
                $phone_number = $restaurant->SMS_phone;
            }
            else{
                $phone_number = '';
            }
            
            if(!empty($phone_number) && $phone_number != null){
                
                $phone_number = str_replace(array(' ',':',';','-','/'), array('',',',',', '',''), $phone_number);
                $phone_numbers = explode(",", $phone_number);
               
                if(count($phone_numbers)){
                    
                    $setting =  Setting::where(["lang" => $restaurant->lang])->first();
                    
                    foreach($phone_numbers as $phone_number){
                        
                        if(strpos($phone_number,"+") === false 
                            && (strpos($phone_number,"00") === false || strpos($phone_number,"00"))){
                            $phone_number = "+".($setting->phone_code).$phone_number;
                        }
                        
                        if(strpos($phone_number,"+".$setting->phone_code) === 0 || strpos($phone_number,"00".$setting->phone_code) === 0)
                        {
               
                        Mail::send($path,
                            ['user' => $user, 'order' => $order, 'restaurant'=> $restaurant,
                                'orders_detail_count'=> count($order->request_order_detail), 'orders_detail_filtered' =>$orders_detail_filtered, 'orders_detail_total_price' => $this->getTotalPrice($order->request_order_detail), 'meal' => $request_menu_filtered, 'new_restaurant' => $new_restaurant, 'currency' => $currency],
                            function ($m) use($restaurant, $setting, $phone_number){
                               
                                $m->from('cesko@gastro-booking.com',  "Gastro Booking");
                                $m->replyTo($restaurant->email, $restaurant->name);
                                $m->to($setting->SMS_email, "Gastro Bookings");
                                $m->subject($phone_number);
                            
                            });
                        }
                    }
                }
            }
        } catch(Exception $e){
            return false;
        }
    }

    public function sendEmailReminder($type, User $user, Order $order, $restaurant, $lang, $orders_detail_filtered, $to, $new_restaurant, $request_menu_filtered)
    {
        $client = app('Dingo\Api\Auth\Auth')->user()->client;

        if ( isset($client->lang) && !empty($client->lang) ) {
            $langSett = $client->lang;
        }
        else{
            $langSett = 'CZE';
        }

        $setting = Setting::where('lang', '=', $langSett)->first();
        $lang = Setting::where('lang', '=', $lang)->first()->short_name;
        app()->setLocale($lang);

        if ($type == 'new'){
            $subject = Lang::get('main.MAIL.GASTRO_BOOKING_-_REQUEST');
        }
        else if ($type == 'update'){
            $subject = Lang::get('main.MAIL.GASTRO_BOOKING_-_REQUEST_UPDATE');
        } else {
            $subject = Lang::get('main.MAIL.GASTRO_BOOKING_-_CANCELLATION_REQUEST');
        }
        $currency = $setting->currency_short;

        $path = 'emails.requestMeal.request_'.$type;
        if ($to == 'rest') {
            $path = 'emails.requestMeal.restaurant_request_' . $type;
        }
        $orderType = ($order->pick_up === 'Y') ? "Pick up" : (($order->delivery_address && $order->delivery_phone) ? "Delivery" : "Order");

        try {
            Mail::send($path,
                ['user' => $user, 'order' => $order, 'restaurant'=> $restaurant,
                    'orders_detail_count'=> count($order->request_order_detail), 'orders_detail_filtered' => $orders_detail_filtered,
                    'orders_detail_total_price' => $this->getTotalPrice($order->request_order_detail), 'meal' => $request_menu_filtered, 'new_restaurant' => $new_restaurant, 'currency' => $currency],
                function ($m) use($user, $restaurant, $to, $type, $orderType, $setting, $new_restaurant, $subject){
                    if ($restaurant) {
                        $restaurant_email = $restaurant->email;
                        $restaurant_name = $restaurant->name;
                    }
                    else{
                        $restaurant_email = $setting->SMS_email;
                        $restaurant_name = $new_restaurant['name'];
                    }
                    if ($to == 'user'){
                        $m->from('cesko@gastro-booking.com', "Gastro Booking");
                        $m->replyTo($restaurant_email, $restaurant_name);
                        $m->to($user->email, $user->name);

                    }
                    else if ($to == 'rest'){
                        $m->from('cesko@gastro-booking.com',  "Gastro Booking");
                        $m->replyTo($user->email, $user->name);
                        $m->to($restaurant_email, $restaurant_name);
                    }
                    if ($type == 'new'){
                        $m->subject($subject);
                    }
                    else if ($type == 'update'){
                        $m->subject($subject);
                    } else {
                        $m->subject($subject);
                    }
                });
        } catch(Exception $e){
            return false;
        }
    }

    public function confirmRequest($request){

        if ($request->request_id) {

            $statusArr = array(0, 1);
            $requestStatus = MealRequest::where('ID', '=', $request->request_id)->first();
            if ( $requestStatus->ID_orders ) {
                $orderStatus = Order::where('ID', '=', $requestStatus->ID_orders)->first();
                if ( !in_array($orderStatus->status, $statusArr) ) {
                    if ( $orderStatus->status == 1 ) {
                        $openTab = "pendingRequests";
                    }
                    else if ( $orderStatus->status == 2 ) {
                        $openTab = "confirmedRequests";
                    }
                    else if ( $orderStatus->status == 3 ) {
                        $openTab = "cancelledRequests";
                    }
                    else{
                        $openTab = "newRequests";
                    }
                    return ['message' => "status changed", 'openTab' => $openTab];
                }
            }


            $requests = MealRequest::find($request->request_id);
            $status = $requests->status;
            $countCancelRequests = 0;
            if ( $status == 'N' ) {
                if ( isset($request->order_detail_staus) && !empty($request->order_detail_staus) ) {
                    $countOrderDetail = count($request->order_detail_staus)-1;
                    for ($i=0; $i <= $countOrderDetail; $i++) {
                        OrderDetail::where('ID', $request->order_detail_staus[$i])
                                         ->update(['status' => 3]);
                    }
                }

                $requests->unread = 'R';
                $requests->timestamps = false;
                if ($requests->save()) {
                    $order = Order::find($requests->ID_orders);
                    $comment = (isset($request->comment)) ? $request->comment : '';
                    Order::where('ID', $requests->ID_orders)->update(['comment' => $comment]);


                    $client = Client::find($order->ID_client);
                    $restaurantID = $requests->ID_restaurant;
                    $restaurant = Restaurant::find($restaurantID);
                    $new_restaurant = '';
                    $user = User::find($client->ID_user);

                    $lang = $request->input('lang', 'CZE');

                    $getMealRequest = MealRequest::with(['orders','orders.request_order_detail', 'orders.request_order_detail.requestParam', 'orders.request_order_detail.requestMenu'])->whereHas('orders', function ($query) use($requests){
                        $query->where('ID', '=', $requests->ID_orders);
                    })->orderBy('ID', 'DESC')->first();

                }

                if ($requests->ID_restaurant) {
                    $this->updateSyncServOwnTable($requests->ID_restaurant, 1);
                }

                return ['message' => "client success"];
            }
            else{
                $cancelOrderDetailID = [];
                if ( isset($request->order_detail_staus) && !empty($request->order_detail_staus) ) {
                    $cancelOrderDetailID = $request->order_detail_staus;
                }

                foreach ($cancelOrderDetailID as $key => $value) {
                    $cancelOrderDetailID[] = $value;
                }


                $requests = new MealRequest();
                $requests = MealRequest::find($request->request_id);
                $requests->status = $request->request_status;
                $requests->unread = 'R';
                $requests->timestamps = false;
                if ($requests->save()) {
                    $order = Order::find($requests->ID_orders);
                    Order::where('ID', $requests->ID_orders)->update(['status' => 2]);


                    $getOrderDetails = OrderDetail::where('ID_orders', '=', $requests->ID_orders)->get();
                    $checkConfirm = '';
                    $checkcancel = '';
                    foreach ($getOrderDetails as $value) {
                        if ( in_array($value->ID, $cancelOrderDetailID) ) {
                            $countCancelRequests++;
                            OrderDetail::where('ID', $value->ID)->update(['status' => 3]);
                        }
                        else{
                            $checkStatus = 'D';
                            if ( $value->status != 3) {
                                $checkStatus = 'C';
                                OrderDetail::where('ID', $value->ID)->update(['status' => 2]);
                                
                                $requestMenuID = $value->ID_request_menu;
                                $getIngDetails = RequestIngredient::where('ID_request_menu', '=', $requestMenuID)->get();
                                foreach ($getIngDetails as $key => $getIngDetail) {
                                    if ($getIngDetail->status_confirmed == 'U') {
                                        $ingredient = RequestIngredient::find($getIngDetail->ID);
                                        $ingredient->status_confirmed = 'C';
                                        $ingredient->timestamps = false;
                                        $ingredient->save();
                                    }
                                }
                            }
                        }
                    }


                    $client = Client::find($order->ID_client);
                    if ($requests->ID_restaurant) {
                        $restaurantID = $requests->ID_restaurant;
                        $restaurant = Restaurant::find($restaurantID);
                        $new_restaurant = '';
                    }
                    else{
                        $restaurant = '';
                        $new_restaurant = array();
                        $new_restaurant['name'] = (($requests->new_restaurant)) ? $requests->new_restaurant : '';
                        $new_restaurant['address'] = (($requests->new_address)) ? $requests->new_address : '';
                    }

                    $user = User::find($client->ID_user);

                    $getMealRequest = MealRequest::with(['orders','orders.request_order_detail', 'orders.request_order_detail.requestParam', 'orders.request_order_detail.requestMenu'])->whereHas('orders', function ($query) use($requests){
                        $query->where('ID', '=', $requests->ID_orders);
                    })->orderBy('ID', 'DESC')->first();

                    $getOrderDetails = OrderDetail::where('ID_orders', '=', $requests->ID_orders)->get();
                    foreach ($getOrderDetails as $value) {
                        if ( $value->status != 3) {
                            $checkConfirm = 1;
                        }
                        else{
                            $checkcancel = 1;
                        }
                    }

                    $lang = $request->input('lang', 'CZE');

                    $sent = $this->sendUpdateEmailReminder('update', $user, $getMealRequest, $restaurant, $lang, 'user', $new_restaurant,$checkcancel, $checkConfirm);


                    if ( $countCancelRequests != 0 ) {
                        $sent_rest = $this->sendUpdateEmailReminder('update', $user, $getMealRequest, $restaurant, $restaurant->lang ?: 'CZE', 'rest', $new_restaurant,$checkcancel, $checkConfirm);
                        $sent_sms = $this->sendOtherSMSEmailReminder(
                            'update_short',
                            app('Dingo\Api\Auth\Auth')->user(),
                            $getMealRequest,
                            $restaurant,
                            $restaurant->lang ?: 'cs',
                            'admin',
                            $new_restaurant
                        );
                    }

                    if ($requests->ID_restaurant) {
                        $this->updateSyncServOwnTable($requests->ID_restaurant, 1);
                    }
                    return ['message' => "success"];
                }
                else{
                    return ['message' => "Error"];
                }
            }

        }
        else{
            return ['message' => "Error"];
        }
    }


    public function sendUpdateEmailReminder($type, User $user, $getMealRequest, $restaurant, $lang, $to, $new_restaurant,$checkcancel, $checkConfirm)
    {
        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        if ( isset($client->lang) && !empty($client->lang) ) {
            $langSett = $client->lang;
        }
        else{
            $langSett = 'CZE';
        }
        $setting = Setting::where('lang', '=', $langSett)->first();
        $lang = Setting::where('lang', '=', $lang)->first()->short_name;
        app()->setLocale($lang);
        $subject = Lang::get('main.MAIL.GASTRO_BOOKING_-_CLIENT_CONFIRMED_REQUEST');
        $currency = $setting->currency_short;

        $path = 'emails.requestMeal.request_'.$type;
        try {
            Mail::send($path,
                ['user' => $user, 'order' => $getMealRequest['orders'], 'restaurant'=> $restaurant,
                    'orders_detail_count'=> count($getMealRequest['orders']->request_order_detail), 'orders_detail_filtered' => $getMealRequest['orders']->request_order_detail, 'orders_detail_total_price' => $this->getTotalPrice($getMealRequest['orders']->request_order_detail), 'new_restaurant' => $new_restaurant, 'currency' => $currency, 'checkcancel' => $checkcancel, 'checkConfirm' => $checkConfirm],
                function ($m) use($user, $restaurant, $to, $type, $setting, $new_restaurant, $subject){
                    if ($restaurant) {
                        $restaurant_email = $restaurant->email;
                        $restaurant_name = $restaurant->name;
                    }
                    else{
                        $restaurant_email = $setting->SMS_email;
                        $restaurant_name = $new_restaurant['name'];
                    }
                    if ($to == 'user'){
                        $m->from('cesko@gastro-booking.com', "Gastro Booking");
                        $m->replyTo($restaurant_email, $restaurant_name);
                        $m->to($user->email, $user->name);

                    }
                    else if ($to == 'rest'){
                        $m->from('cesko@gastro-booking.com',  "Gastro Booking");
                        $m->replyTo($user->email, $user->name);
                        $m->to($restaurant_email, $restaurant_name);
                    }
                    $m->subject($subject);
                    
                });
        } catch(Exception $e){
            return false;
        }
    }

    public function cancelRequest($request){
        $requests = new MealRequest();
        if ($request->ID) {

            $statusArr = array(0, 1, 2);
            $requestStatus = MealRequest::where('ID', '=', $request->ID)->first();
            if ( $requestStatus->ID_orders ) {
                $orderStatus = Order::where('ID', '=', $requestStatus->ID_orders)->first();
                if ( !in_array($orderStatus->status, $statusArr) ) {
                    if ( $orderStatus->status == 1 ) {
                        $openTab = "pendingRequests";
                    }
                    else if ( $orderStatus->status == 2 ) {
                        $openTab = "confirmedRequests";
                    }
                    else if ( $orderStatus->status == 3 ) {
                        $openTab = "cancelledRequests";
                    }
                    else{
                        $openTab = "newRequests";
                    }
                    return ['message' => "success", 'openTab' => $openTab];
                }
            }

            $requests = MealRequest::find($request->ID);
            $requests->status = 'C';
            $requests->unread = 'R';
            $lang = $request->input('lang', 'CZE');

            $requests->timestamps = false;
            if ($requests->save()) {
                Order::where('ID', $requests->ID_orders)->update(['status' => 3]);

                if ($requests->ID_restaurant) {
                    $restaurantID = $requests->ID_restaurant;
                    $restaurant = Restaurant::find($restaurantID);
                    $new_restaurant = '';

                    $this->updateSyncServOwnTable($requests->ID_restaurant, 1);
                }
                else{
                    $restaurant = '';
                    $new_restaurant = array();
                    $new_restaurant['name'] = (($requests->new_restaurant)) ? $requests->new_restaurant : '';
                    $new_restaurant['address'] = (($requests->new_address)) ? $requests->new_address : '';
                }

                $getMealRequest = MealRequest::with(['orders','orders.request_order_detail','orders.request_order_detail.requestMenu'])->whereHas('orders', function ($query) use($requests){
                    $query->where('ID', '=', $requests->ID_orders);
                })->orderBy('ID', 'DESC')->first();

                $sent = $this->sendCancelEmailReminder('cancel', app('Dingo\Api\Auth\Auth')->user(), $getMealRequest, $restaurant, $lang, 'user', $new_restaurant);

                $sent_rest = $this->sendCancelEmailReminder('cancel', app('Dingo\Api\Auth\Auth')->user(), $getMealRequest, $restaurant, $restaurant->lang ?: 'CZE', 'rest', $new_restaurant);

                $sent_sms = $this->sendOtherSMSEmailReminder(
                    'cancel_short',
                    app('Dingo\Api\Auth\Auth')->user(),
                    $getMealRequest,
                    $restaurant,
                    $restaurant->lang ?: 'cs',
                    'admin',
                    $new_restaurant
                );

                return ['message' => "success"];
            }
            else{
                return ['message' => "Error"];
            }
        }
        else{
            return ['message' => "Error"];
        }

    }

    public function sendOtherSMSEmailReminder($type, User $user, $getMealRequest, $restaurant, $clientLang, $to, $new_restaurant)
    {
        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        if ( isset($client->lang) && !empty($client->lang) ) {
            $langSett = $client->lang;
        }
        else{
            $langSett = 'CZE';
        }
        $setting = Setting::where('lang', '=', $langSett)->first();
        $lang = Setting::where('lang', '=', $clientLang)->first()->short_name;
        app()->setLocale($lang);

        $currency = $setting->currency_short;

        $path = 'emails.requestMeal.request_'.$type;

        try {
            
            if ( isset($restaurant->SMS_phone) ) {
                $phone_number = $restaurant->SMS_phone;
            }
            else{
                $phone_number = '';
            }
            
            if(!empty($phone_number) && $phone_number != null){
                
                $phone_number = str_replace(array(' ',':',';','-','/'), array('',',',',', '',''), $phone_number);
                $phone_numbers = explode(",", $phone_number);
               
                if(count($phone_numbers)){
                    
                    $setting =  Setting::where(["lang" => $restaurant->lang])->first();
                    
                    foreach($phone_numbers as $phone_number){
                        
                        if(strpos($phone_number,"+") === false 
                            && (strpos($phone_number,"00") === false || strpos($phone_number,"00"))){
                            $phone_number = "+".($setting->phone_code).$phone_number;
                        }
                        
                        if(strpos($phone_number,"+".$setting->phone_code) === 0 || strpos($phone_number,"00".$setting->phone_code) === 0)
                        {
               
                        Mail::send($path,
                            ['user' => $user, 'order' => $getMealRequest['orders'], 'restaurant'=> $restaurant,
                                'orders_detail_count'=> count($getMealRequest['orders']->request_order_detail), 'orders_detail_filtered' =>$getMealRequest['orders']->request_order_detail,
                                'orders_detail_total_price' => $this->getTotalPrice($getMealRequest['orders']->request_order_detail), 'new_restaurant' => $new_restaurant, 'currency' => $currency],
                            function ($m) use($restaurant, $setting, $phone_number){
                               
                                $m->from('cesko@gastro-booking.com',  "Gastro Booking");
                                $m->replyTo($restaurant->email, $restaurant->name);
                                $m->to($setting->SMS_email, "Gastro Bookings");
                                $m->subject($phone_number);
                            
                            });
                        }
                    }
                }
            }
        } catch(Exception $e){
            return false;
        }
    }


    public function sendCancelEmailReminder($type, User $user, $getMealRequest, $restaurant, $lang, $to, $new_restaurant)
    {
        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        if ( isset($client->lang) && !empty($client->lang) ) {
            $langSett = $client->lang;
        }
        else{
            $langSett = 'CZE';
        }
        $setting = Setting::where('lang', '=', $langSett)->first();
        $lang = Setting::where('lang', '=', $lang)->first()->short_name;
        app()->setLocale($lang);
        $subject = Lang::get('main.MAIL.GASTRO_BOOKING_-_CANCELLATION_REQUEST');
        $currency = $setting->currency_short;

        $path = 'emails.requestMeal.request_'.$type;

        try {
            Mail::send($path,
                ['user' => $user, 'order' => $getMealRequest['orders'], 'restaurant'=> $restaurant,
                    'orders_detail_count'=> count($getMealRequest['orders']->request_order_detail), 'orders_detail_filtered' => $getMealRequest['orders']->request_order_detail,
                    'orders_detail_total_price' => $this->getTotalPrice($getMealRequest['orders']->request_order_detail), 'new_restaurant' => $new_restaurant, 'currency' => $currency],
                function ($m) use($user, $restaurant, $to, $type, $setting, $new_restaurant, $subject){
                    if ($restaurant) {
                        $restaurant_email = $restaurant->email;
                        $restaurant_name = $restaurant->name;
                    }
                    else{
                        $restaurant_email = $setting->SMS_email;
                        $restaurant_name = $new_restaurant['name'];
                    }
                    if ($to == 'user'){
                        $m->from('cesko@gastro-booking.com', "Gastro Booking");
                        $m->replyTo($restaurant_email, $restaurant_name);
                        $m->to($user->email, $user->name);

                    }
                    else if ($to == 'rest'){
                        $m->from('cesko@gastro-booking.com',  "Gastro Booking");
                        $m->replyTo($user->email, $user->name);
                        $m->to($restaurant_email, $restaurant_name);
                    }
                    $m->subject($subject);
                    
                });
        } catch(Exception $e){
            return false;
        }
    }

    public function changeStatus($request_id){
        if ($request_id) {
            $checkStatus = MealRequest::find($request_id);
            if ($checkStatus->unread == 'C' ) {
                $requests = MealRequest::find($request_id);
                $requests->unread = 'N';
                $requests->timestamps = false;
                $requests->save();

                if ($requests->ID_restaurant) {
                    $this->updateSyncServOwnTable($requests->ID_restaurant, 1);
                }
            }
            return ['message' => "success"];
        }
        else{
            return ['message' => "Error"];
        }
    }

    public function getFriends(){
        $user = app('Dingo\Api\Auth\Auth')->user();

        return $user;
    }

    public function getCurrentUser(){
        $user = app('Dingo\Api\Auth\Auth')->user();
        return $user;
    }

    public function update(Request $request){
        $client = Client::find($request['id']);
        $client->ID_diet = isset($request["ID_diet"]) ? $request["ID_diet"] : null;
        $client->address = isset($request["address"]) ? $request["address"] : null;
        $client->phone = isset($request["phone"]) ? $request["phone"] : null;
        $client->account_number = isset($request["account_number"]) ? $request["account_number"] : null;
        $client->bank_code = isset($request["bank_code"]) ? $request["bank_code"] : null;
        $client->lang = isset($request["lang"]) ? $request["lang"] : null;
        $client->latitude = isset($request["latitude"]) ? $request["latitude"] : null;
        $client->longitude = isset($request["longitude"]) ? $request["longitude"] : null;
        $client->location = isset($request["location"]) ? $request["location"] : null;
        $client->save();

        if (isset($request["password"]) && $request["password"]) {
            $user = app('Dingo\Api\Auth\Auth')->user();
            $user->password = Hash::make($request["password"]);
            $user->save();
        }
    }

    private function getTotalPrice($orders_detail)
    {
        $price = 0;
        foreach ($orders_detail as $order_detail) {
            if ($order_detail->status != 3){
                if ($order_detail->is_child){
                    $price += ($order_detail->price_child && $order_detail->price_child > 0) ? $order_detail->price_child : $order_detail->price;
                } else {
                    $price += $order_detail->price;
                }
            }

        }
        return $price;
    }

    private function getDiffInTimeCustom(Carbon $time1, Carbon $time2)
    {
        $time1 = date('Y-m-d', strtotime( $time1->toDateTimeString() ) );
        $time2 = date('Y-m-d', strtotime( $time2->toDateTimeString() ) );
        return strtotime($time1) - strtotime($time2);
    }

    private function getDiffInTime(Carbon $time1, Carbon $time2)
    {
        return strtotime($time1->toDateTimeString()) - strtotime($time2->toDateTimeString());
    }

    public function getPrintData(Request $request, $request_id){
        $requests = MealRequest::find($request_id);
        $order = Order::find($requests->ID_orders);
        $current_time = Carbon::now("Europe/Prague");
        $orders_detail_copy = $order->request_order_detail;
        $currency = "";
        foreach ($orders_detail_copy as $order_detail) {
            $serve_time = new Carbon($order_detail->serve_at);
            $diffInMinutes = $this->getDiffInTime($serve_time, $current_time);
            $order_detail->difference = $diffInMinutes;
            if (!$currency){
                $currency = $order_detail->currency;
            }
        }
        $filtered_order_detail = $orders_detail_copy->sortBy("difference")->first();
        $order->cancellation = \DateTime::createFromFormat('Y-m-d H:i:s', $filtered_order_detail->serve_at)->format('d.m.Y H:i');
        $order->currency = $currency;

        $orders_detail_filtered = [];
        $order->request_order_detail = $order->request_order_detail->sortBy("serve_at");
        $checkConfirm = '';
        $checkcancel = '';
        foreach ($order->request_order_detail as $order_detail) {
            $orders_detail_filtered[] = $order_detail;
            if ( $order_detail->status != 3) {
                $checkConfirm = 1;
            }
            else{
                $checkcancel = 1;
            }
        }

        if ($requests->ID_restaurant) {
            $restaurantID = $requests->ID_restaurant;
            $restaurant = Restaurant::find($restaurantID);
            $new_restaurant = '';
        } else {
            $restaurant = '';
            $new_restaurant = array();
            $new_restaurant['name'] = (($requests->new_restaurant)) ? $requests->new_restaurant : '';
            $new_restaurant['address'] = (($requests->new_address)) ? $requests->new_address : '';
        }

        return ['order' => $order,
            'restaurant' => $restaurant,'new_restaurant' => $new_restaurant, 'user' => app('Dingo\Api\Auth\Auth')->user(), 'currency' => $currency,
            'orders_detail_count'=> count($order->request_order_detail), 'orders_detail_filtered' => $orders_detail_filtered,
            'orders_detail_total_price' => $this->getTotalPrice($order->request_order_detail), 'checkConfirm' => $checkConfirm, 'checkcancel' => $checkcancel];

        return ["requestError" => "Request error!"];

    }
    // remuneration

    public function getClient($n) {
        $user = app('Dingo\Api\Auth\Auth')->user();
        if ($n['0'] == 0) {
            $client = app('Dingo\Api\Auth\Auth')->user()->client->ID;
        }
        else{
            $client = $n['0'];
        }
        $currentClient = Client::where("ID", $client)->get();
        $setting = Setting::where("lang", $user->client->lang)->get();
        $output['data']= array(
            "client" => $currentClient,
            "setting" => $setting
        );
        return $output;
    }

}