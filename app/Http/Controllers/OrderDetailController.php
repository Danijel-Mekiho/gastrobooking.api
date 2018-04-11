<?php

namespace App\Http\Controllers;

use App\Entities\Order;
use App\Entities\OrderDetail;
use App\Entities\Restaurant;
use App\Entities\PatronList;

use App\Entities\RestaurantType;
use App\Entities\Setting;
use App\Repositories\OrderRepository;
use App\Repositories\MenuListRepository;
use App\Repositories\OrderDetailRepository;
use App\Repositories\QuizRepository;
use App\Repositories\RestaurantRepository;
use App\Transformers\OrderDetailTransformer;
use App\Transformers\OrderTransformer;
use App\Transformers\AllOrderTransformer;
use Carbon\Carbon;
use Dingo\Api\Routing\Helpers;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;
use View;

use App\Http\Requests;

class OrderDetailController extends Controller
{
    use Helpers;
    public $ordersDetailRepository;
    public $orderRepository;
    public $menuListRepository;
    public $restaurantRepository;
    public $perPage = 5;
    private $currency = "";

    public function __construct(OrderDetailRepository $orderDetailRepository, MenuListRepository $menuListRepository, OrderRepository $orderRepository, QuizRepository $quizRepository, RestaurantRepository $restaurantRepository)
    {
        $this->ordersDetailRepository = $orderDetailRepository;
        $this->menuListRepository = $menuListRepository;
        $this->orderRepository = $orderRepository;
        $this->quizRepository = $quizRepository;
        $this->restaurantRepository = $restaurantRepository;
    }

    public function getOrderDetails($restaurantId){

        $orders_detail = $this->ordersDetailRepository->all($restaurantId);
        if ($orders_detail){
            return $this->response->collection($orders_detail, new OrderDetailTransformer($this->menuListRepository));
        }

        return ["error" => "You have no orders"];
    }
    public function getEnableDiscount($restaurantId){
        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        $orderId = $this->orderRepository->getClientOrder($client->ID, $restaurantId);
        $lang = DB::table('restaurant')->where( 'id', $restaurantId )->value('lang');

        $client_per = DB::table('quiz_client')->where('ID_client', $client->ID)->where('lang', $lang)->sum('quiz_percentage');
        $prize_per = DB::table('quiz_prize')->where('ID_client', $client->ID)->where('lang', $lang)->sum('percentage');

        return ($client_per - $prize_per);
    }
    public function getTables($restaurantId){
        $result = DB::table('rooms')->where('ID_restaurant', $restaurantId)->get();

        return $result;
    }

    public function getOrdersDetailByStatus(Request $request, $orderId){
        $orders_detail = $this->ordersDetailRepository->getOrdersDetailByStatus($request->status, $orderId, $this->perPage);
        if ($orders_detail){
            return $this->response->paginator($orders_detail, new OrderDetailTransformer($this->menuListRepository));
        }
        return ["error" => "You have no orders detail"];
    }

    public function getOrders()
    {
        $orders = $this->ordersDetailRepository->getOrders();
        if ($orders){
            return $this->response->collection($orders, new OrderTransformer($this->menuListRepository));
        }

    }

    public function getOrdersByStatus(Request $request)
    {
        $orders = $this->ordersDetailRepository->getAllOrders($this->perPage);
        foreach ($orders as $order) {
            $orders_detail = $order->orders_detail;
            $order->orders_detail = $orders_detail->filter(function($item){
                if ($item->side_dish == "0"){
                    return true;
                }
            });

        }
        if ($orders){
            return $this->response->paginator($orders, new AllOrderTransformer($this->menuListRepository));
        }
        return ["error" => "You have no orders"];
    }

    public function store(Request $request){
        $menuList = \App\Entities\MenuList::find($request->orders_detail['ID_menu_list']);
        if (!$menuList) {
            return ["error" => "Menu does not exist!"];
        }

        if ($menuList->book_latest) {
            $date = new Carbon($request->orders_detail['date']);
            $bookLastest = new Carbon($menuList->book_latest);

            $now = Carbon::now();
            $now->setTimezone($date->timezone);

            if ($now->toDateString() == $date->toDateString() && ($now->hour * 3600 + $now->minute * 60 + $now->second) > ($bookLastest->hour * 3600 + $bookLastest->minute * 60 + $bookLastest->second))
                return ["latest" => "1", "booking_latest" => $bookLastest->format('H:i')];
        }

        $orders_detail = $this->ordersDetailRepository->store($request);

        // update sync_serv_own table
        if (isset($request->orders_detail["ID_restaurant"]))
            $this->restaurantRepository->updateSyncServOwnTable($request->orders_detail["ID_restaurant"]);

        if ($orders_detail){
            return $this->response->item($orders_detail, new OrderDetailTransformer($this->menuListRepository));
        }
        return ["error" => "You have already ordered this item!"];
    }

    public function update(Request $request){
        $orders_detail = $this->ordersDetailRepository->respond($request);
        return $orders_detail;
    }

    public function updateOrdersDetail(Request $request){
        if ($request->has("orders_detail")){
            $order_obj = Order::find($request->orders_detail[0]['ID_orders']);
            $changed = false;
            foreach ($request->orders_detail as $detail) {
                $order_detail = OrderDetail::find($detail["ID_orders_detail"]);
                if ($order_detail->status != $detail["status"]){
                    $changed = true;
                } else if (count($detail["sideDish"]["data"])){
                    $order_detail_array = $order_detail->sideDish->toArray();
                    for ($i = 0; $i < count($detail["sideDish"]["data"]); $i++){
                        if (array_key_exists($i, $order_detail_array) && (!isset($detail["sideDish"]["data"][$i]["status"])
                                || $detail["sideDish"]["data"][$i]["status"] != $order_detail_array[$i]["status"])){
                            $sd_order_detail = OrderDetail::find($detail["sideDish"]["data"][$i]["ID_orders_detail"]);
                            $sd_order_detail->status = $detail["sideDish"]["data"][$i]["status"];
                            $sd_order_detail->save();
                            $changed = true;
                        }
                    }

                }
                if ($detail["status"] == 6 && $order_detail->status != 2){
                    $order_detail->delete();
                } else if ($order_detail->status != 2 && $order_detail->status != 4){
                    $order_detail->status = $detail["status"];
                    $order_detail->x_number = (int)$detail['x_number'];
                    $order_detail->serve_at = new Carbon($detail['serve_at']);
                    $order_detail->is_child = $detail['is_child'] ? 1 : 0;
                    $order_detail->price = isset($detail['t_price']) && $detail['t_price'] ? $detail['t_price'] : 0;
                    $order_detail->side_dish = $detail['side_dish'];
                    $order_detail->comment = $detail['comment'];
                    $order_detail->ID_client = $detail['ID_client'];
                    if ($order_detail->side_dish){
                        $main_dish = OrderDetail::find($order_detail->side_dish);
                        $order_detail->serve_at = $main_dish ? $main_dish->serve_at : $order_detail->serve_at;
                        $order_detail->ID_client = $main_dish ? $main_dish->ID_client : $order_detail->ID_client;
                    }
                }
                $order_detail->save();
            }

            // update sync_serv_own table
            $this->restaurantRepository->updateSyncServOwnTable($order_obj->ID_restaurant, 1);

            $cancellation = $this->getCancellationTime($order_obj);
            $order_obj->cancellation = $cancellation["serve_at"];
            $order_obj->currency = $cancellation["currency"];
            $another_order_email = Order::find($order_obj->ID);
            $orders_detail_filtered = [];
            $another_order_email->orders_detail = $another_order_email->orders_detail->sortBy("serve_at");

            $order_obj = $this->orderRepository->checkAndCancel($order_obj->ID);
            if ($request->has("save") && $changed){
                $email_type = 'cancel';
                if ($order_obj->status == 3) {
                    $email_type = 'cancel';
                } else if ($order_obj->status != 5) {
                    $email_type = 'update';
                }

                $sent = $this->ordersDetailRepository->sendEmailReminder($email_type, app('Dingo\Api\Auth\Auth')->user(), $order_obj, $order_obj->restaurant,
                    $request->lang ? $request->lang : 'cz', $orders_detail_filtered, 'user');
                $sent_rest = $this->ordersDetailRepository->sendEmailReminder($email_type, app('Dingo\Api\Auth\Auth')->user(), $order_obj, $order_obj->restaurant,
                    $order_obj->restaurant->lang ?: 'cz', $orders_detail_filtered, 'rest');
				$sent_sms = $this->ordersDetailRepository->sendSMSEmailReminder($email_type . '_short', app('Dingo\Api\Auth\Auth')->user(), $order_obj,
                    $order_obj->restaurant,$order_obj->restaurant->lang ?: 'cz', $orders_detail_filtered, 'admin');
            }

            return ["success" => "Order Details updated successfully"];
        }
        return ["error" => "'orders_detail' key not found!"];
    }

    public function updateOrders(Request $request){
        $order = $request->has("order");

        if ($order){
            $order_obj = Order::find($request->order["ID_orders"]);

            if ($request->order["status"] == 6 && $order_obj->status != 2){
                $orders_detail = $order_obj->orders_detail;
                foreach ($orders_detail as $item) {
                    $item->delete();
                }
                $order_obj->delete();

            }
            else if ($order_obj->status != 2 && $order_obj->status != 4){
                $order_obj->status = $request->order["status"];
                $order_obj->comment = $request->order["comment"];
                $order_obj->persons = $request->order["persons"];
                $order_obj->pick_up = (isset($request->order["pick_up"]) && $request->order["pick_up"]) ? "Y" : "N";
                $order_obj->table_until = isset($request->order["table_until"]) ? $request->order["table_until"] : null;
                $order_obj->ID_tables = isset($request->order["ID_tables"]) ? $request->order["ID_tables"] : null;
                $order_obj->gb_discount = isset($request->order["gb_discount"]) ? $request->order["gb_discount"] : null;

                if (isset($request->order["delivery"]) && $request->order["delivery"] === true ) {
                    $order_obj->delivery_address = isset($request->order["delivery_address"]) ? $request->order["delivery_address"] : null;
                    $order_obj->delivery_phone = isset($request->order["delivery_phone"]) ? $request->order["delivery_phone"] : null;
                    $order_obj->delivery_latitude = isset($request->order["delivery_latitude"]) ? $request->order["delivery_latitude"] : null;
                    $order_obj->delivery_longitude = isset($request->order["delivery_address"]) ? $request->order["delivery_longitude"] : null;
                }
                else {
                    $order_obj->delivery_address = null;
                    $order_obj->delivery_phone = null;
                    $order_obj->delivery_latitude = null;
                    $order_obj->delivery_longitude = null;
                }
                /*if ($order_obj->gb_discount && $order_obj->gb_discount > 0){
                    $lang = DB::table('restaurant')->where( 'id', $request->order["ID_restaurant"] )->value('lang');
                    $this->quizRepository->storeQuizPrize( $request->order["ID_orders"], $request->order["gb_discount"], $request->order["prize"], $lang);
                }*/

                $order_obj->save();
            }

            // update sync_serv_own table
            $this->restaurantRepository->updateSyncServOwnTable($order_obj->ID_restaurant, 1);


            $cancellation = $this->getCancellationTime($order_obj);
            $order_obj->cancellation = $cancellation["serve_at"];
            $order_obj->currency = $cancellation["currency"];
            if ($order_obj->status == 3){
                foreach ($order_obj->orders_detail as $o_detail) {
                    $o_detail = OrderDetail::find($o_detail->ID);
                    $o_detail->status = 3;
                    $o_detail->save();
                };

                $order_obj->orders_detail = $order_obj->orders_detail->sortBy("serve_at");

                $sent = $this->ordersDetailRepository->sendEmailReminder('cancel', app('Dingo\Api\Auth\Auth')->user(), $order_obj, $order_obj->restaurant,
                    $request->lang ? $request->lang : 'cz', $order_obj->orders_detail, 'user');
                $sent_rest = $this->ordersDetailRepository->sendEmailReminder('cancel', app('Dingo\Api\Auth\Auth')->user(), $order_obj, $order_obj->restaurant,
                    $order_obj->restaurant->lang ?: 'cz', $order_obj->orders_detail, 'rest');

				$sent_sms = $this->ordersDetailRepository->sendSMSEmailReminder(
				    'cancel_short',
                    app('Dingo\Api\Auth\Auth')->user(),
                    $order_obj, $order_obj->restaurant,
                    $order_obj->restaurant->lang ?: 'cz',
                    $order_obj->orders_detail,
                    'admin'
                );

            }
            return ["success" => "Order updated successfully"];
        }
        return ["error" => "'order' key not found!"];

    }

    public function getCancellationTime($order)
    {
        $order_detail = $order->orders_detail;
        $filtered = $order_detail->filter(function($item){
            $current_time = Carbon::now();
            $serve_time = new Carbon($item->serve_at);
            $diffInMinutes = $serve_time->diffInMinutes($current_time, false);
            $item->difference = $diffInMinutes;
            $this->currency = $item->menu_list->currency;
            return true;
        });
        $filtered = $filtered->sortByDesc("difference");
        $filtered_order_detail = $filtered->first();
        if ($filtered_order_detail && $filtered_order_detail->difference >= 0){
            return [
                "status" => "error",
                "currency" => $this->currency ,
                "serve_at" => \DateTime::createFromFormat('Y-m-d H:i:s', $filtered_order_detail->serve_at)->format('d.m.Y H:i') ];
        }
        return $filtered_order_detail ? [
            "status" => "success",
            "currency" => $this->currency ,
            "serve_at" => \DateTime::createFromFormat('Y-m-d H:i:s', $filtered_order_detail->serve_at)->format('d.m.Y H:i')] : "";
    }

    public function deleteOrder(Request $request, $orderId){
        $order_obj = Order::find($orderId);
        $order = $this->ordersDetailRepository->deleteOrder($orderId);
        if ($order){
            $response = $this->response->item($order, new OrderTransformer($this->menuListRepository));
            return $response;
        }
        $order_obj->cancellation = $this->getCancellationTime($order_obj);
        $sent = $this->ordersDetailRepository->sendEmailReminder('cancel', app('Dingo\Api\Auth\Auth')->user(), $order_obj, $order_obj->restaurant,
            $order_obj->restaurant->lang ?: 'cz', $order_obj->orders_detail, 'user');
        $sent_rest = $this->ordersDetailRepository->sendEmailReminder('cancel', app('Dingo\Api\Auth\Auth')->user(), $order_obj, $order_obj->restaurant,
            $request->lang ? $request->lang : 'cz', $order_obj->orders_detail, 'rest');
        return ["error" => "Order not found!"];
    }

    public function deleteOrderDetail($orderDetailId){
        $order_detail = $this->ordersDetailRepository->deleteOrderDetail($orderDetailId);
        if ($order_detail){
            $response = $this->response->item($order_detail, new OrderDetailTransformer($this->menuListRepository));
            return $response;
        }
        return ["error" => "Order detail not found!"];
    }

    public function getOrder($orderId)
    {
        $order = $this->ordersDetailRepository->getOrder($orderId);
        if ($order){
            $response = $this->response->item($order, new OrderTransformer($this->menuListRepository));
            return $response;
        }
        return ["error" => "Order not found!"];
    }

    public function getOrderForDashboard($orderId)
    {
        $order = $this->ordersDetailRepository->getOrder($orderId);
        $orders_detail = $order->orders_detail;
        $order->orders_detail = $orders_detail->filter(function($item){
            if ($item->side_dish == "0"){
                return true;
            }
        });
        if ($order){
            $response = $this->response->item($order, new OrderTransformer($this->menuListRepository));
            return $response;
        }
        return ["error" => "Order not found!"];
    }
    
    public function getSumPrice(Request $request)
    {
        return $this->ordersDetailRepository->getSumPrice($request);
    }

	public function getSumPriceBetweenDates(Request $request)
	{
			return $this->ordersDetailRepository->getSumPriceBetweenDates($request);
	}

    public function getOrderDetailCount()
    {
        return $this->ordersDetailRepository->getOrderDetailCount();
    }

    public function deleteSideDish($orderDetailId){
        $deleted = $this->ordersDetailRepository->removeSideDish($orderDetailId);
        $message = $deleted ? 'The side dish was successfully deleted' : 'Failed to delete side dish';

        return response()->json([ 'message'=> $message, 'id'=>$orderDetailId]);
    }

    public function printOrder(Request $request, $lang, $orderId) {
        app()->setLocale($lang ?: 'en');
        $render_data = $this->ordersDetailRepository->getPrintData($request, $orderId);
        $view = View::make('emails.order.order_new_print', $render_data);
        $contents = $view->render();
        return $contents;
    }

    public function getDiscountCodes(Request $request)
    {
        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        $discount_codes = DB::table('discount_code')
            //->where('ID_client', NULL)
            ->get();
        return response()->json(['data' => $discount_codes]);
    }

    public function getRestaurantType(){
        $languages = Setting::all()
            ->pluck('lang', 'short_name')
            ->toArray();

        foreach ($languages as $code => &$lang) {
            $lang = RestaurantType::where(['lang' => $lang])->pluck('name' , 'cust_order');
        }

        return response()->json(['data'=> $languages]);
    }

    public function getWinBooking($restaurantId, $clientId, $now, $from_date = "", $to_date = "") {
        $whereSql = "";

        if ($from_date == "" && $to_date == "") {
            $whereSql = "WHERE to_date > DATE('$now') AND from_date <= DATE('$now') AND ID_restaurant = $restaurantId ";
        } else {
            $whereSql = "WHERE to_date = DATE('$to_date') AND from_date = DATE('$from_date') AND ID_restaurant = $restaurantId ";
        }

        $query =    "SELECT ID_restaurant, from_date, to_date, GROUP_CONCAT(ID_client) clients, GROUP_CONCAT(CONCAT(ID_client, '_', IFNULL(created_at, ''))) client_created_at, MAX(IF(status = 1, ID_client, 0)) patronage_clientId, minimal, overtake ".
                    "FROM patron_list ".$whereSql;

        $patron = \DB::select($query)[0];
        $retResult = new \stdClass;
        if ($patron->ID_restaurant == null) {
            $restaurant = Restaurant::where('ID', $restaurantId)->first();

            if ($restaurant)
                $retResult->win_booking = $restaurant->patron_minimal;
            else
                $retResult->win_booking = 0;
            $retResult->win_clientId = 0;

            $retResult->highest_booking = 0;
            $retResult->highest_clientId = 0;
            $retResult->second_highest_booking = 0;

            $retResult->client_all_booking = 0;
            $retResult->client_finished_booking = 0;

            $retResult->patron_booking = 0;

            $retResult->finished_orders = array();
            return $retResult;
        }
        $rest = $patron->ID_restaurant;
        $fromDate = $patron->from_date;
        $toDate = $patron->to_date;
        $clientIds = $patron->clients;

        $minimal = $patron->minimal;
        $overtake = $patron->overtake;

        $createdTimes = explode(",", $patron->client_created_at);
        $patronage_clientId = $patron->patronage_clientId;
        $win_booking = 0;
        $win_clientId = 0;
        $highest_booking = 0;
        $second_booking = 0;
        $highest_cliendId = 0;
        $patron_booking = 0;

        $created = array();
        foreach ($createdTimes as $time) {
            $list = explode("_", $time);
            $created[$list[0]] = $list[1];
        }

        $orderSql =     "SELECT orders.ID_client, SUM(IF(orders_detail.status IN (0, 1, 2,4), orders_detail.price, 0)) all_booking, SUM(IF(orders_detail.serve_at < '$now' AND orders_detail.status IN (2,4), orders_detail.price, 0)) finished_booking ".
                        "FROM orders, orders_detail, restaurant, setting ".
                        "WHERE orders.ID = orders_detail.ID_orders ".
                                "AND orders.ID_restaurant = restaurant.ID ".
                                "AND restaurant.lang = setting.lang ".
                                "AND orders_detail.currency = setting.currency_short ".
                                "AND orders.ID_restaurant = $restaurantId ".
                                "AND orders_detail.serve_at >= '$fromDate' AND orders_detail.serve_at < '$toDate' ".
                        "GROUP BY orders.ID_client ";
        $result = \DB::select($orderSql);

        $orders_finisehd = array();
        $orders_all = array();
        foreach ($result as $order) {
            $orders_finisehd[$order->ID_client] = $order->finished_booking;
            $orders_all[$order->ID_client] = $order->all_booking;
        }
        $finishedOrders = array();
        $allOrders = array();
        $activateClients = explode(",", $clientIds);
        foreach($activateClients as $actClientId) {
            $friendsSql =   "SELECT ID_client FROM client_group WHERE approved = 'Y' AND ID_grouped_client = $actClientId AND ID_client NOT IN ($clientIds) ".
                            " UNION ALL ".
                            "SELECT ID_grouped_client ID_client FROM client_group WHERE approved = 'Y' AND ID_client = $actClientId AND ID_grouped_client NOT IN ($clientIds) ";
            $friends = \DB::select($friendsSql);

            $finishedOrders[$actClientId] = 0;
            if (array_key_exists($actClientId, $orders_finisehd)) {
                $finishedOrders[$actClientId] += $orders_finisehd[$actClientId];
            }

            $allOrders[$actClientId] = 0;
            if (array_key_exists($actClientId, $orders_all)) {
                $allOrders[$actClientId] += $orders_all[$actClientId];
            }

            foreach($friends as $friend) {
                $id = $friend->ID_client;
                if (array_key_exists($id, $orders_finisehd)) {
                    $finishedOrders[$actClientId] += $orders_finisehd[$id];
                }
                if (array_key_exists($id, $orders_all)) {
                    $allOrders[$actClientId] += $orders_all[$id];
                }
            }

            if ($finishedOrders[$actClientId] > $highest_booking) {
                $second_booking = $highest_booking;
                $highest_booking = $finishedOrders[$actClientId];
                $highest_cliendId = $actClientId;
            } else if ($finishedOrders[$actClientId] == $highest_booking && $finishedOrders[$actClientId] > 0) {
                $second_booking = $highest_booking;
                if ($actClientId == $patronage_clientId) {
                    $highest_cliendId = $actClientId;
                } else if ($highest_cliendId != $patronage_clientId && $created[$actClientId] < $created[$highest_cliendId]) {
                    $highest_cliendId = $actClientId;
                }
            } else if ($finishedOrders[$actClientId] > $second_booking) {
                $second_booking = $finishedOrders[$actClientId];
            }

            if ($actClientId == $patronage_clientId) {
                $patron_booking = $finishedOrders[$actClientId];
            }
        }

        if ($patron_booking >= $minimal && $highest_booking >= $overtake) {
            $win_booking = $highest_booking;
            $win_clientId = $highest_cliendId;
        } else if ($patron_booking >= $minimal && $highest_booking < $overtake) {
            $win_booking = $overtake;
            if ($clientId == $patronage_clientId)
                $win_booking = $minimal;
            $win_clientId = $patronage_clientId;
        } else if ($patron_booking < $minimal && $highest_booking >= $minimal) {
            $win_booking = $highest_booking;
            $win_clientId = $highest_cliendId;
        } else {
            $win_booking = $minimal;
            $win_clientId = 0;
        }
        $retResult->win_booking = $win_booking;
        $retResult->win_clientId = $win_clientId;

        $retResult->highest_booking = $highest_booking;
        $retResult->highest_clientId = $highest_cliendId;
        $retResult->second_highest_booking = $second_booking;

        $retResult->client_all_booking = isset($allOrders[$clientId]) ? $allOrders[$clientId] : 0;
        $retResult->client_finished_booking = isset($finishedOrders[$clientId]) ? $finishedOrders[$clientId] : 0;

        $retResult->patron_booking = $patron_booking;

        $retResult->finished_orders = $finishedOrders;
        return $retResult;
    }

    public function getAllPatronage(Request $request) {
        $user = app('Dingo\Api\Auth\Auth')->user();
        $clientId = $user->client->ID;
        $location = $user->client->location;
        $lang = $user->client->lang;

        $page = $request->page;
        $limit = 5;
        $offset = ($page - 1) * $limit;
        $lat = $user->client->latitude;
        $lng = $user->client->longitude;

        $business = $request->business;
        $distance = $request->distance;

        $patronOnly = $request->patronOnly;
        $b_query = " WHERE R.patron_days > 0 AND R.status IN ('A', 'N') ";

        if($business!=0){
            $b_query .= " AND R.`ID_restaurant_type` = $business";
        }

        if ($patronOnly == "true") {
            $b_query .= " AND (Patron.status IS NULL OR Patron.status = 0) ";
        }

        $d_query = "";
        if($distance!=0){
            $d_query = " HAVING distance < $distance";
        }

        $new = "ROUND(111.045 * DEGREES(ACOS(COS(RADIANS(R.`latitude`)) * COS(RADIANS($lat)) * COS(RADIANS(R.`longitude` - $lng))+ SIN(RADIANS(R.`latitude`))* SIN(RADIANS($lat)))),2) as distance";

        $today = $request->now;

        $photoQuery =   " SELECT t1.item_id, t1.upload_directory, t1.minified_image_name ".
                        " FROM photo t1, (SELECT item_id, upload_directory, minified_image_name, MIN(IF(item_type = 'exterior', 1, IF(item_type = 'interior', 2, 3))) min_num  FROM photo GROUP BY item_id) t2 ".
                        " WHERE t1.item_id = t2.item_id AND IF(t1.item_type = 'exterior', 1, IF(t1.item_type = 'interior', 2, 3)) = t2.min_num ".
                        " GROUP BY t1.item_id ";

        $patronQuery =  " SELECT ID_restaurant, MAX(IF(ID_client = $clientId, IFNULL(status, 0), -1)) client_status, MAX(IFNULL(status, 0)) status ".
                        " FROM patron_list ".
                        " WHERE from_date <= DATE('$today') AND to_date > DATE('$today') ".
                        " GROUP BY ID_restaurant ";

        $query =    " SELECT R.`id`, R.`name`, R.`short_descr`, R.`city`, R.`street`, R.`currency`, R.`ID_restaurant_type`, R.`lang`, ".
                        " R.`patron_promillage` as promillage, R.`patron_minimal` as patron_minimal, R.currency, CONCAT(Photo.upload_directory, Photo.minified_image_name) photo, ".
                        " IFNULL(Patron.client_status, -1) as client_status, IFNULL(Patron.status, 0) as status, $new ".
                    " FROM restaurant as R ".
                        " LEFT JOIN ($photoQuery) Photo ON R.id = Photo.item_id ".
                        " LEFT JOIN ($patronQuery) Patron ON R.id = Patron.ID_restaurant ".
                        " $b_query  $d_query ".
                    " ORDER BY distance ";

        $patronages = \DB::select($query." limit ".$offset.", ".$limit);

        foreach ($patronages as $patronage) {
            $result = $this->getWinBooking($patronage->id, $clientId, $today);
            $patronage->win_booking = $result->win_booking;
        }
        $patronagesCount = \DB::select($query);
        if($patronages){
            return ["data" => $patronages , 'count'=>count($patronagesCount) , "location"=>$location, "lang"=>$lang];
        }
        return ["error" => "No sent friend requests found!" , "location"=>$location, "count"=>0];
    }

    public function patronActivate(Request $request) {
        $user = app('Dingo\Api\Auth\Auth')->user();
        $restaurantID = $request->restaurantID;
        $now = $request->now;

        $restaurant = Restaurant::find($restaurantID);

        $fromDate = new Carbon($now);
        $toDate = new Carbon($now);
        $toDate->addDay($restaurant->patron_days);

        $oldpatronList = PatronList::where('ID_restaurant', $restaurantID)->where('from_date', '<=', $fromDate)->where('to_date', '>', $fromDate)->first();

        $patronList = new PatronList();
        $patronList->ID_client = $user->client->ID;
        $patronList->ID_restaurant = $restaurantID;
        if ($oldpatronList) {
            $patronList->from_date = $oldpatronList->from_date;
            $patronList->to_date = $oldpatronList->to_date;

            $patronList->minimal = $oldpatronList->minimal;
            $patronList->overtake = $oldpatronList->overtake;
        } else {
            $patronList->from_date = $fromDate;
            $patronList->to_date = $toDate;

            $patronList->minimal = $restaurant->patron_minimal;
            $patronList->overtake = $restaurant->patron_overtake;
        }
        $patronList->promillage = $restaurant->patron_promillage;
        $patronList->status = 0;
        $patronList->save();


        return ["success" => "1"];
    }
    public function getActivePatronage(Request $request) {
        $user = app('Dingo\Api\Auth\Auth')->user();
        $clientId = $user->client->ID;
        $page = $request->page;

        $limit = 5;
        $offset = ($page - 1) * $limit;

        $now = $request->now;
        // $now = '2017-06-29 23:00:00';

        // get active patronage list
        $query =    "SELECT MAX(IF(patron.ID_client = $clientId, patron.id, 0)) id, GROUP_CONCAT(patron.ID_client) clientIds, patron.ID_restaurant, patron.from_date, patron.to_date, patron.minimal, patron.overtake, ".
                            "MAX(IF(patron.ID_client = $clientId, patron.status, 0)) client_status, MAX(IF(patron.status = 1, patron.ID_client, 0)) patron_id, MAX(patron.status) status, patron.promillage, ".
                            "rest.name rest_name, rest.currency ".
                    "FROM patron_list patron, restaurant rest ".
                    "WHERE patron.ID_restaurant = rest.id ".
                            "AND patron.ID_restaurant IN (SELECT DISTINCT ID_restaurant FROM patron_list WHERE ID_client = $clientId AND patron_list.from_date <= '$now' AND patron_list.to_date > '$now') ".
                            "AND patron.from_date <= '$now' AND patron.to_date > '$now' ".
                    "GROUP BY patron.ID_restaurant, patron.from_date, patron.to_date ".
                    "ORDER BY patron.to_date ASC, patron.from_date ASC, patron.id ASC ";

        $patronages = \DB::select($query." limit ".$offset.", ".$limit);
        foreach ($patronages as $patron) {
            $result = $this->getWinBooking($patron->ID_restaurant, $clientId, $now, $patron->from_date, $patron->to_date);

            $patron->patron_finished_booking = $result->patron_booking;
            $patron->client_all_booking = $result->client_all_booking;
            $patron->client_finished_booking = $result->client_finished_booking;
            if ($result->highest_clientId == $clientId)
                $patron->highest_finished_booking = $result->second_highest_booking;
            else
                $patron->highest_finished_booking = $result->highest_booking;

            $patron->win_booking = $result->win_booking;
            $patron->win_clientId = $result->win_clientId;
        }

        $patronagesCount = \DB::select($query);
        if($patronages) {
            return ["data" => $patronages , 'count'=>count($patronagesCount), 'clientId'=>$clientId ];
        }
        return ["error" => "No sent friend requests found!"];
    }
    public function patronRemove(Request $request) {
        $user = app('Dingo\Api\Auth\Auth')->user();
        $clientId = $user->client->ID;
        $id = $request->id;

        $patron = PatronList::where('id', $id)->where('ID_client', $clientId)->first();
        $patron->delete();

        return ["success" => "1"];
    }
    public function getHistoryPatronage(Request $request) {
        $user = app('Dingo\Api\Auth\Auth')->user();
        $clientId = $user->client->ID;
        $page = $request->page;
        $limit = 5;
        $offset = ($page - 1) * $limit;

        $now = $request->now;
        // $now = '2017-05-29 23:00:00';

        $query =    "SELECT patron.ID_restaurant, patron.from_date, patron.to_date, IFNULL(patron.minimal, 0) minimal, IFNULL(patron.overtake, 0) overtake, IFNULL(patron.patron, 0) patron, IFNULL(patron.finished, 0) finished, IFNULL(patron.highest, 0) highest, IFNULL(patron.missing, 0) missing, IFNULL(patron.status, 0) status, ".
                            "IFNULL(before_patron.patron_exist, 0) patron_exist, IFNULL(after_patron.status, 0) winner, rest.name rest_name, rest.currency ".
                    "FROM patron_list patron ".
                            "LEFT JOIN (".
                                "SELECT DISTINCT ID_restaurant, from_date, to_date, MAX(IF(ID_client <> $clientId, IFNULL(status, 0), 0)) patron_exist ".
                                "FROM patron_list ".
                                "GROUP BY ID_restaurant, from_date, to_date".
                            ") before_patron ON before_patron.from_date = patron.from_date AND before_patron.to_date = patron.to_date AND before_patron.ID_restaurant = patron.ID_restaurant ".
                            "LEFT JOIN (SELECT DISTINCT ID_restaurant, from_date, to_date, ID_client, status FROM patron_list WHERE status = 1) after_patron ON after_patron.from_date = patron.to_date AND after_patron.ID_client = $clientId AND after_patron.ID_restaurant = patron.ID_restaurant, ".
                            "restaurant rest ".
                    "WHERE patron.ID_restaurant = rest.id ".
                            "AND patron.ID_client = $clientId ".
                            "AND patron.to_date <= DATE('$now') ".
                    "ORDER BY patron.to_date DESC, patron.from_date DESC, patron.id DESC ";

        $patronages = \DB::select($query." limit ".$offset.", ".$limit);

        $patronagesCount = \DB::select($query);
        if($patronages){
            return ["data" => $patronages , 'count'=>count($patronagesCount), 'clientId'=>$clientId];
        }
        return ["error" => "No sent friend requests found!"];
    }
    public function getBillingPatronage(Request $request) {
        $user = app('Dingo\Api\Auth\Auth')->user();
        $clientId = $user->client->ID;
        $page = $request->page;
        $limit = 5;
        $offset = ($page - 1) * $limit;

        $now = $request->now;
        // $now = '2017-05-29 23:00:00';

        $sumOrderSql =      "SELECT patron_list.ID_restaurant, patron_list.from_date, patron_list.to_date, ".
                                    "SUM(IF(orders_detail.status IN (0,1,2,4), orders_detail.price, 0)) all_booking, ".
                                    "SUM(IF(DATE(orders_detail.serve_at) < '$now', IF(orders_detail.status IN (2,4), orders_detail.price, 0), 0)) finished_booking ".
                            "FROM (SELECT patron_list.ID_restaurant, patron_list.from_date, patron_list.to_date FROM patron_list GROUP BY patron_list.ID_restaurant, patron_list.from_date, patron_list.to_date) patron_list ".
                                    "LEFT JOIN orders ON patron_list.ID_restaurant = orders.ID_restaurant ".
                                    "LEFT JOIN restaurant ON patron_list.ID_restaurant = restaurant.ID ".
                                    "LEFT JOIN setting ON restaurant.lang = setting.lang ".
                                    "LEFT JOIN orders_detail ON orders.ID = orders_detail.ID_orders AND patron_list.from_date <= DATE(orders_detail.serve_at) AND patron_list.to_date > DATE(orders_detail.serve_at) AND setting.currency_short = orders_detail.currency ".
                            "WHERE orders.ID = orders_detail.ID_orders ".
                            "GROUP BY patron_list.ID_restaurant, patron_list.from_date, patron_list.to_date ";

        $orderSql =     "SELECT orders.ID_restaurant, orders.from_date, orders.to_date, ".
                                "SUM(IFNULL(orders.bookings, 0)) bookings, SUM(IFNULL(orders.persons, 0)) persons, ".
                                "SUM(IFNULL(orders.tables, 0)) tables, SUM(IFNULL(orders.pickup, 0)) pickup, SUM(IFNULL(orders.delivery, 0)) delivery ".
                        "FROM (".
                                "SELECT patron_list.ID_restaurant, patron_list.from_date, patron_list.to_date, 1 bookings, IFNULL(orders.persons, 0) persons, IF(orders.table_until IS NOT NULL, 1, 0) tables, IF(orders.pick_up = 'Y', 1, 0) pickup, IF(orders.delivery_address IS NOT NULL, 1, 0) delivery ".
                                "FROM patron_list ".
                                        "LEFT JOIN restaurant ON patron_list.ID_restaurant = restaurant.ID ".
                                        "LEFT JOIN setting ON restaurant.lang = setting.lang ".
                                        "LEFT JOIN orders_detail ON patron_list.from_date <= DATE(orders_detail.serve_at) AND patron_list.to_date > DATE(orders_detail.serve_at) AND orders_detail.currency = setting.currency_short ".
                                        "LEFT JOIN orders ON orders_detail.ID_orders = orders.ID AND patron_list.ID_restaurant = orders.ID_restaurant ".
                                "WHERE orders.ID IS NOT NULL ".
                                "GROUP BY patron_list.ID_restaurant, patron_list.from_date, patron_list.to_date, orders.ID) orders ".
                        "GROUP BY orders.ID_restaurant, orders.from_date, orders.to_date";

        // get active patronage list
        $activeQuery =  "SELECT 0 history, patron.ID id, patron.ID_restaurant, patron.from_date, patron.to_date, patron.minimal, patron.overtake, patron.promillage, patron.missing, ".
                                "MAX(IFNULL(sum_orders.all_booking, 0)) all_booking, ".
                                "MAX(IFNULL(sum_orders.finished_booking, 0)) finished_booking, ".
                                "MAX(IFNULL(orders.bookings, 0)) bookings, MAX(IFNULL(orders.persons, 0)) persons, ".
                                "MAX(IFNULL(orders.tables, 0)) tables, MAX(IFNULL(orders.pickup, 0)) pickup, MAX(IFNULL(orders.delivery, 0)) delivery, rest.name rest_name, rest.currency ".
                        "FROM patron_list patron ".
                                "LEFT JOIN ($sumOrderSql) sum_orders ON patron.from_date = sum_orders.from_date AND patron.to_date = sum_orders.to_date AND patron.ID_restaurant = sum_orders.ID_restaurant ".
                                "LEFT JOIN ($orderSql) orders ON patron.ID_restaurant = orders.ID_restaurant AND patron.from_date = orders.from_date AND patron.to_date = orders.to_date ".
                                ", restaurant rest ".
                        "WHERE patron.ID_restaurant = rest.id ".
                                "AND patron.ID_restaurant IN (SELECT DISTINCT ID_restaurant FROM patron_list WHERE ID_client = $clientId AND patron_list.from_date <= '$now' AND patron_list.to_date > '$now' AND patron_list.status = 1) ".
                                "AND patron.from_date <= '$now' AND patron.to_date > '$now' ".
                        "GROUP BY patron.ID_restaurant, patron.from_date, patron.to_date ";

        $runningSumQuery =  "SELECT IFNULL(SUM(all_booking), 0) all_booking, IFNULL(SUM(finished_booking), 0) finished_booking, IFNULL(SUM(finished_booking * promillage / 1000), 0) profit, ".
            "IFNULL(SUM(bookings), 0) bookings, IFNULL(SUM(persons), 0) persons, IFNULL(SUM(tables), 0) tables, IFNULL(SUM(pickup), 0) pickup, IFNULL(SUM(delivery), 0) delivery ".
            "FROM ($activeQuery) t1 ";
        $running = \DB::select($runningSumQuery)[0];

        $runningQuery = "SELECT patron.ID_restaurant, patron.from_date, patron.to_date FROM patron_list patron WHERE ID_client = $clientId AND status = 1 AND from_date <= DATE('$now') AND to_date > DATE('$now') GROUP BY patron.ID_restaurant, patron.from_date, patron.to_date ";
        $runningResult = \DB::select($runningQuery);
        $missingSum = 0;
        foreach ($runningResult as $patron) {
            $result = $this->getWinBooking($patron->ID_restaurant, $clientId, $now, $patron->from_date, $patron->to_date);

            $patron->client_finished_booking = $result->client_finished_booking;
            $patron->win_booking = $result->win_booking;

            $missingSum += $result->win_booking - $patron->client_finished_booking;
        }
        $running->missing_booking = $missingSum;

        $historyQuery =     "SELECT 1 history, patron.ID id, patron.ID_restaurant, patron.from_date, patron.to_date, patron.minimal, patron.overtake, patron.promillage, patron.missing, ".
                                    "0 all_booking, MAX(IFNULL(sum_orders.finished_booking, 0)) finished_booking, ".
                                    "MAX(IFNULL(orders.bookings, 0)) bookings, MAX(IFNULL(orders.persons, 0)) persons, ".
                                    "MAX(IFNULL(orders.tables, 0)) tables, MAX(IFNULL(orders.pickup, 0)) pickup, MAX(IFNULL(orders.delivery, 0)) delivery, rest.name rest_name, rest.currency ".
                            "FROM patron_list patron ".
                                    "LEFT JOIN ($sumOrderSql) sum_orders ON patron.from_date = sum_orders.from_date AND patron.to_date = sum_orders.to_date AND patron.ID_restaurant = sum_orders.ID_restaurant ".
                                    "LEFT JOIN ($orderSql) orders ON patron.ID_restaurant = orders.ID_restaurant AND patron.from_date = orders.from_date AND patron.to_date = orders.to_date ".
                                    ", restaurant rest ".
                            "WHERE patron.ID_restaurant = rest.id ".
                                    "AND patron.ID_client = $clientId AND patron.status = 1 ".
                                    "AND patron.to_date <= DATE('$now') ".
                            "GROUP BY patron.ID_restaurant, patron.from_date, patron.to_date ";

        $query = $activeQuery." UNION ALL ".$historyQuery." ORDER BY history, to_date DESC, from_date DESC, id DESC ";

        $patronages = \DB::select($query." limit ".$offset.", ".$limit);

        foreach ($patronages as $patron) {
            if ($patron->history == 1) break;
            $result = $this->getWinBooking($patron->ID_restaurant, $clientId, $now, $patron->from_date, $patron->to_date);

            $patron->patron_finished_booking = $result->patron_booking;
            $patron->client_all_booking = $result->client_all_booking;
            $patron->client_finished_booking = $result->client_finished_booking;
            if ($result->highest_clientId == $clientId)
                $patron->highest_finished_booking = $result->second_highest_booking;
            else
                $patron->highest_finished_booking = $result->highest_booking;

            $patron->win_booking = $result->win_booking;
            $patron->win_clientId = $result->win_clientId;
        }

        $historySumQuery =  "SELECT IFNULL(SUM(all_booking), 0) all_booking, IFNULL(SUM(finished_booking), 0) finished_booking, IFNULL(SUM(finished_booking * promillage / 1000), 0) profit, ".
                                    "IFNULL(SUM(bookings), 0) bookings, IFNULL(SUM(persons),0) persons, IFNULL(SUM(tables), 0) tables, IFNULL(SUM(pickup), 0) pickup, IFNULL(SUM(delivery), 0) delivery ".
                            "FROM ($historyQuery) t1 ";
        $finished = \DB::select($historySumQuery)[0];

        $countQuery = "SELECT patron.ID_restaurant FROM patron_list patron WHERE ID_client = $clientId AND status = 1 GROUP BY patron.ID_restaurant, patron.from_date, patron.to_date ";
        $patronagesCount = \DB::select($countQuery);


        $query = "SELECT IFNULL(SUM(IF(pay_date IS NOT NULL, value, 0)), 0) paid, IFNULL(SUM(IF(pay_date IS NULL, value, 0)), 0) unpaid  FROM patron_payment WHERE ID_client = $clientId ";
        $paid = \DB::select($query)[0];
        if($patronages){
            return ["data" => $patronages , 'count'=>count($patronagesCount), 'clientId'=>$clientId,  'paid'=>$paid, "running"=>$running, "finished"=>$finished];
        }
        return ["error" => "No sent friend requests found!"];
    }
    public function sendAmount(Request $request){
        $headers = "MIME-Version: 1.0" . "\r\n";
        $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";

        // More headers
        $headers .= "From: $request->from" . "\r\n";
        $headers .= 'Cc: patron@gastro-booking.com' . "\r\n";

        $result0 = mail('patron@gastro-booking.com','Send Amount message', $request->input('content'),$headers);

        $result = $result0 ? "Message sent. Thank you." : "Sorry. Message send failed.";
        return $result;
    }

    public function patronUpdate() {
        $patronList = new PatronList();
        $now = new Carbon();

        $query =    "SELECT ID_restaurant, from_date, to_date, "."GROUP_CONCAT(ID_client) clients, GROUP_CONCAT(CONCAT(ID_client, '_', IFNULL(created_at, ''))) client_created_at, MAX(IF(status = 1, ID_client, 0)) patronage_clientId, minimal, overtake ".
                    "FROM patron_list ".
                    "WHERE to_date <= DATE('$now') AND updated = 0 ".
                    "GROUP BY ID_restaurant, from_date, to_date ".
                    "ORDER BY ID_restaurant, from_date, to_date ";

        $pastList = \DB::select($query);
        //$pastList = PatronList::where('to_date', '<=', $now)->where('updated', 0)->orderBy('ID_restaurant')->orderBy('from_date', 'asc');
        foreach($pastList as $patron) {
            $result = $this->getWinBooking($patron->ID_restaurant, 0, $now, $patron->from_date, $patron->to_date);
            $rest = $patron->ID_restaurant;
            $fromDate = $patron->from_date;
            $toDate = $patron->to_date;
            $clientIds = $patron->clients;
            $activateClients = explode(",", $clientIds);
            foreach($activateClients as $clientId) {
                $patron = PatronList::where('to_date', $toDate)->where('from_date', $fromDate)->where('ID_restaurant', $rest)->where('ID_client', $clientId)->first();
                if ($patron) {
                    $patron->patron = $result->patron_booking;
                    $patron->finished = isset($result->finished_orders[$clientId]) ? $result->finished_orders[$clientId] : 0;
                    if ($result->highest_booking != 0 && $result->highest_booking == $patron->finished) {
                        $patron->highest = $result->second_highest_booking;
                    } else {
                        $patron->highest = $result->highest_booking;
                    }
                    if ($clientId != $result->win_clientId)
                        $patron->missing = $result->win_booking - $patron->finished;
                    else
                        $patron->missing = 0;
                    $patron->updated = 1;

                    $patron->save();
                }
            }

            if ($result->win_clientId == 0) continue;

            $restList = Restaurant::where('ID', $rest)->first();

            $nextFromDate = new Carbon($toDate);
            $nextToDate = new Carbon($toDate);
            $nextToDate->addDay($restList->patron_days);

            $newPatron = PatronList::where('to_date', $nextToDate)->where('from_date', $nextFromDate)->where('ID_restaurant', $rest)->where('ID_client', $result->win_clientId)->first();
            if ($newPatron) {
                //$newPatron->status = 1;
                $newPatron->save();
            } else {
                $newPatron = new PatronList();
                $newPatron->ID_client = $result->win_clientId;
                $newPatron->ID_restaurant = $rest;
                $newPatron->from_date = $nextFromDate;
                $newPatron->to_date = $nextToDate;

                $newPatron->minimal = $restList->patron_minimal;
                $newPatron->overtake = $restList->patron_overtake;
                $oldpatron = PatronList::where('ID_restaurant', $rest)->where('from_date', $fromDate)->where('to_date', $toDate)->where('ID_client', $result->win_clientId)->first();

                if($oldpatron) {
                    $newPatron->promillage = $oldpatron->promillage;
                } else {
                    $newPatron->promillage = $restList->patron_promillage;
                }

                $newPatron->status = 1;
                $newPatron->save();
            }
        }

    }

    // remuneration
    public function getAllOrdersWithDetail(Request $request)
    {
        $orders = $this->ordersDetailRepository->getAllOrdersWithDetail($request);
        return ["data" => $orders];
    }

    public function getAllOrdersArray(Request $request)
    {
        $orders = $this->ordersDetailRepository->getAllOrdersArray($request);
        return ["data" => $orders];
    }
}
