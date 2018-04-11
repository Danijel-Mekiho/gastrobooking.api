<?php

namespace App\Http\Controllers;
use App\Entities\Order;
use App\Entities\Client;
use App\Entities\User;
use App\Entities\Restaurant;
use App\Entities\RateSetting;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;
use App\Http\Requests;

class OrderController extends Controller {
    
    public function rateOrder(Request $request) {
        $result = 0;
        
        $user = app('Dingo\Api\Auth\Auth')->user();
        $user_id = $user->id;
        
        // get data payload
        $data = $request->all();

        // get order
        $order = Order::where(["ID" => $data['ID_orders']])->first();    
        
        // checkpoint :
        // user is the one that created the order
        // order has not been rated yet
        $rated = (bool) $order->rate_client;      
        
        $client = Client::where(["ID" => $order->ID_client])->first();
        $owner_id = $client->ID_user;

        if(!$rated && $user_id == $owner_id) {
        
            // get restaurant
            $restaurant = Restaurant::where(["id" => $order->ID_restaurant])->first();
            // get lang
            $lang = $restaurant->lang;
            // get settings : read settings from `rate_setting` table
            $setting = RateSetting::where(["lang" => $lang])->first();            
                        
            // reduce tree : get relevant data for each tree (compute averages)
            foreach($data['rate_order']['rate_detail'] as $id => $detail) {
                if(empty($detail['collapsed'])) {
                    $data['rate_order']['rate_detail'][$id]['detail_rating'] = ($detail['rate_menu']['taste_rating'] * $setting->taste +  $detail['rate_menu']['amount_rating'] * $setting->amount + $detail['rate_menu']['look_rating'] * $setting->look) /  ($setting->taste + $setting->amount + $setting->look);
                }
            }

            if(empty($data['rate_order']['menu_collapsed'])) {            
                $detail_sum = 0;
                foreach($data['rate_order']['rate_detail'] as $detail) {
                    $detail_sum += $detail['detail_rating'];                
                } 
                $data['rate_order']['menu_rating'] = $detail_sum / count($data['rate_order']['rate_detail']);
            }

            if(empty($data['rate_order']['surround_collapsed'])) {
                $data['rate_order']['surround_rating'] = ($data['rate_order']['rate_surround']['pleasant_rating'] * $setting->pleasant + $data['rate_order']['rate_surround']['toilet_rating'] * $setting->toilet + $data['rate_order']['rate_surround']['air_rating'] * $setting->air) / ($setting->pleasant + $setting->toilet + $setting->air);
            }

            if(empty($data['rate_order']['service_collapsed'])) {
                $data['rate_order']['service_rating'] = ($data['rate_order']['rate_service']['tableset_rating'] * $setting->laytable + $data['rate_order']['rate_service']['quick_rating'] * $setting->quick + $data['rate_order']['rate_service']['helpful_rating'] * $setting->helpful) / ($setting->laytable + $setting->quick + $setting->helpful);                
            }
            
            if(empty($data['collapsed'])) {
                $data['rc_rating'] = ($data['rate_order']['menu_rating'] * $setting->menu +  $data['rate_order']['service_rating'] * $setting->service + $data['rate_order']['surround_rating'] * $setting->surround) /  ($setting->menu + $setting->service + $setting->surround);
            }

            // store rating
 
            DB::table('rate_client')->insert([
                'ID_orders' => $order->ID, 
                'ID_client' => $order->ID_client,
                'rc_rating' => $data['rc_rating'],
                'comment'   => $data['comment']
            ]);
            
            if(empty($data['collapsed'])) {               
                DB::table('rate_order')->insert([
                    'ID_orders'         => $order->ID,
                    'menu_rating'       => $data['rate_order']['menu_rating'],
                    'surround_rating'   => $data['rate_order']['surround_rating'],
                    'service_rating'    => $data['rate_order']['service_rating']         
                ]);
            }
            
            if(empty($data['rate_order']['surround_collapsed'])) {            
                DB::table('rate_surround')->insert([
                    'ID_orders'         => $order->ID,
                    'pleasant_rating'   => $data['rate_order']['rate_surround']['pleasant_rating'],
                    'toilet_rating'     => $data['rate_order']['rate_surround']['toilet_rating'],
                    'air_rating'        => $data['rate_order']['rate_surround']['air_rating']
                ]); 
            }
            
            if(empty($data['rate_order']['service_collapsed'])) {            
                DB::table('rate_service')->insert([
                    'ID_orders'         => $order->ID,
                    'tableset_rating'   => $data['rate_order']['rate_service']['tableset_rating'],
                    'quick_rating'      => $data['rate_order']['rate_service']['quick_rating'],
                    'helpful_rating'    => $data['rate_order']['rate_service']['helpful_rating']
                ]);
            }

            if(empty($data['rate_order']['menu_collapsed'])) {
                foreach($data['rate_order']['rate_detail'] as $id => $detail) {
                    DB::table('rate_detail')->insert([
                        'ID_orders_detail'  => $detail['ID_orders_detail'],
                        'detail_rating'     => $detail['detail_rating']
                    ]);
                    if(empty($detail['collapsed'])) {                
                        DB::table('rate_menu')->insert([
                            'ID_orders_detail'  => $detail['ID_orders_detail'],
                            'taste_rating'      => $detail['rate_menu']['taste_rating'],
                            'amount_rating'     => $detail['rate_menu']['amount_rating'],
                            'look_rating'       => $detail['rate_menu']['look_rating']
                        ]);
                    }
                }
            }
            
            // compute restaurant new rating
                
            if($restaurant->n_rates <= 0) {
            /*
                Update restaurant rating in fields `rating` and `n_rates` 
                If n_rates = 0 then store rate_client value
                Increment n_rates                
            */
                DB::table('restaurant')
                            ->where('id', $order->ID_restaurant)
                            ->update([
                                'rating'    => $data['rc_rating'],
                                'n_rates'   => 1
                            ]);
            }
            else {
            /*
                If n_rates > 0 then store rate_client value by weighted average using restaurant.n_rates and client total rates - count(rate_client.ID_client)
                Increment n_rates
                e.g.
                restaurant.rating=3, restaurant.n_rates=10, rate_client.rc_rating=4, count(rate_client.ID_client)=2
                Result: (3*10 + 4*2) / (10+2) = 3,1666667 = restaurant.rating, restaurant.n_rates=11

                Display star rating in search result (current place)      
            */
                
                $count = DB::table('rate_client')->where('ID_client', $order->ID_client)->count();
                $rating = ($restaurant->rating * $restaurant->n_rates + $data['rc_rating'] * $count) / ($restaurant->n_rates + $count);
                DB::table('restaurant')
                            ->where('id', $order->ID_restaurant)
                            ->update([
                                'rating'    => $rating,
                                'n_rates'   => $restaurant->n_rates + 1
                            ]);
            }
            
            $result = 1;           
        }

        return ["success" => $result, "data" => $data];
    }    

}