<?php
Route::get('/', function(){
        return view('Welcome');
      });
$api = app('Dingo\Api\Routing\Router');

$api->version('v1', function ($api) {
    $api->get('translate', 'App\Http\Controllers\TranslateController@index');
    $api->post('send_reset_password_email', 'App\Http\Controllers\PasswordController@sendResetLink');
    $api->put('password/reset', 'App\Http\Controllers\PasswordController@resetPassword');
    $api->get('password/reset/token/{token}/email', 'App\Http\Controllers\PasswordController@getTokenEmail');

    $api->group(['prefix' => 'webservice'], function ($api) {
        $api->post('query', 'App\Http\Controllers\WebService\WebServiceController@run');
        $api->get('css', 'App\Http\Controllers\WebService\WebWidgetController@css');
        $api->get('js', 'App\Http\Controllers\WebService\WebWidgetController@js');
    });

      $api->get('restaurant/{id}/frame', 'App\Http\Controllers\FrameController@handle');

      $api->get('auth/{social_type}', 'App\Http\Controllers\SocialAuthController@redirectToProvider');
      $api->get('auth/{social_type}/callback', 'App\Http\Controllers\SocialAuthController@handleProviderCallback');

      $api->group(['prefix' => 'oauth'], function ($api) {
          $api->post('authorize', ['as'=> 'oauth', 'uses'=>'App\Http\Controllers\Auth\AuthController@authorizeClient']);
      });

      $api->post('user', 'App\Http\Controllers\UserController@store');
      $api->put('user', 'App\Http\Controllers\UserController@update');
      $api->post('client', 'App\Http\Controllers\ClientController@store');
      $api->get('email', 'App\Http\Controllers\UserController@sendEmailReminder');
      $api->get('user_exists', 'App\Http\Controllers\UserController@userExistsRoute');
      $api->get('restaurantTypes', 'App\Http\Controllers\RestaurantTypeController@all');
      $api->get('kitchenTypes', 'App\Http\Controllers\KitchenTypeController@all');
      $api->get('tasted', 'App\Http\Controllers\MenuListController@getTasted');
      $api->post('promotionsNearby', 'App\Http\Controllers\MenuListController@getPromotionsNearby');
      $api->post('restaurantsNearby', 'App\Http\Controllers\RestaurantController@getRestaurantsNearby');
      $api->post('restaurants', 'App\Http\Controllers\RestaurantController@all');
      $api->post('restaurantRecommended', 'App\Http\Controllers\RestaurantController@getFirst');
      $api->get('restaurant/{restaurantId}/detail/{type}', 'App\Http\Controllers\RestaurantController@detail');
      $api->post('menu_lists', 'App\Http\Controllers\MenuListController@all');
      $api->get('restaurant/{restaurantId}/organized_menu', 'App\Http\Controllers\RestaurantController@organizeMenu');
      $api->get('restaurant/{restaurantId}/menu_types', 'App\Http\Controllers\RestaurantController@getMenuTypes');
      $api->get('restaurant/{restaurantId}/menu_groups/{menuTypeId}', 'App\Http\Controllers\RestaurantController@getMenuGroups');
      $api->get('restaurant/{restaurantId}/menu_subgroups/{menuGroupId}', 'App\Http\Controllers\RestaurantController@getMenuSubGroups');
      $api->get('restaurant/{restuarantId}/menu_lists/{menuSubGroupId}', 'App\Http\Controllers\RestaurantController@getMenuLists');
      $api->get('restaurant/{restuarantId}/menu_group_and_subgroup_id', 'App\Http\Controllers\RestaurantController@getMenuGroupAndSubGroupId');
      $api->get('orders_detail_count', 'App\Http\Controllers\OrderDetailController@getOrderDetailCount');
      $api->post('orders_sum_price', 'App\Http\Controllers\OrderDetailController@getSumPrice');
      $api->post('orders_sum_price_between_dates', 'App\Http\Controllers\OrderDetailController@getSumPriceBetweenDates');
      $api->get('restaurants', 'App\Http\Controllers\RestaurantController@all');
      $api->get('restaurant/{user_id}/get_active_restaurants', 'App\Http\Controllers\RestaurantController@getActiveRestaurants');
      $api->get('restaurant/{restaurantId}/menu_lists', 'App\Http\Controllers\RestaurantController@menuLists');
      $api->get('diet', 'App\Http\Controllers\DietController@all');

      $api->get('restaurant/current-requests/{requestId}/{serve_at}', 'App\Http\Controllers\RestaurantController@currentRequests');
      $api->get('restaurant/count-missing-booking/{requestId}', 'App\Http\Controllers\RestaurantController@countMissingBooking');
      
      $api->get('discount_codes', 'App\Http\Controllers\OrderDetailController@getDiscountCodes');
      $api->get('place_order/{orderId}/{discountId}', 'App\Http\Controllers\OrderDetailController@placeOrder');

      $api->get('test', 'App\Http\Controllers\TestController@test');
        // set sync_serv_own
        $api->post('restaurantsyncservown', 'App\Http\Controllers\RestaurantController@syncservown');

        // InvoiceSetting Routes
//    $api->get('invoice/get_invoice', 'App\Http\Controllers\InvoiceController@getInvoice');
    $api->get('invoice_setting/get_invoice_setting', 'App\Http\Controllers\InvoiceSettingController@getInvoiceSetting');

    // Invoice Routes
    $api->get('invoice/{restaurant_id}/get_invoice_number', 'App\Http\Controllers\InvoiceController@getInvoiceNumber');
    $api->post('invoice/save_invoice', 'App\Http\Controllers\InvoiceController@setInvoice');
    $api->post('invoice/export_to_pdf_send_email', 'App\Http\Controllers\InvoiceController@exportToPdfSendEmail');
    $api->post('invoice/get_all_invoices', 'App\Http\Controllers\InvoiceController@getAllInvoices');
    $api->get('invoice/{restaurant_id}/get_restaurant_invoices', 'App\Http\Controllers\InvoiceController@getRestaurantInvoices');

    // patron update
    $api->get('patron/update', 'App\Http\Controllers\OrderDetailController@patronUpdate');

    $api->group(['namespace' => 'App\Http\Controllers', 'middleware' => ['api.auth']], function ($api) {
        // User Routes
        $api->get('user/{user_id}', 'UserController@detail');
        $api->get('user/{user_id}/restaurants', 'UserController@getRestaurants');
        $api->get('user/{user_id}/restaurant', 'UserController@getCurrentRestaurant');
        $api->post('user/{user_id}/restaurant', 'UserController@saveRestaurant');
        $api->get('users', 'UserController@all');
        $api->delete('user/{user_id}', 'UserController@delete');
        $api->delete('user/{user_id}/restaurants', 'UserController@deleteRestaurants');
        $api->get('user', 'UserController@getCurrentUser');
        $api->put('user/{user_id}', 'UserController@update');

        // Restaurant Routes
        $api->post('restaurant', 'RestaurantController@store');
        $api->get('restaurants', 'RestaurantController@all');

        $api->post('restaurant/getMenuList', 'RestaurantController@getMenuList');
        $api->post('restaurant/getSetting', 'RestaurantController@getSetting');

        $api->get('restaurant/uuid/{uuid}', 'RestaurantController@findByUuid');
        $api->put('restaurant', 'RestaurantController@store');
        $api->delete('restaurant/{restaurantId}', 'RestaurantController@delete');
        $api->put('restaurant/{restaurantId}/open', 'RestaurantController@updateOpeningHours');
        $api->get('restaurant/{restaurantId}/open', 'RestaurantController@getOpeningHours');

        $api->get('confirmSelf/{restId}', 'RestaurantController@confirmSelf');
        $api->group(['middleware' => ['restaurant-authorization']], function ($api) {
            $api->get('restaurant/{restaurantId}', 'RestaurantController@item');
            $api->get('restaurant_request/{restaurantId}', 'RestaurantController@restaurantRequest');
            $api->get('restaurant_pending_request/{restaurantId}', 'RestaurantController@restaurantPendingRequest');
            $api->get('restaurant_confirm_request/{restaurantId}', 'RestaurantController@restaurantConfirmRequest');
            $api->get('restaurant_cancel_request/{restaurantId}', 'RestaurantController@restaurantCancelRequest');
            $api->get('restaurant_count_unread/{restaurantId}', 'RestaurantController@restaurantCountUnreadRequest');
        });

        $api->post('cancel_restaurant_request', 'RestaurantController@cancelRestaurantRequest');
        $api->post('update-request', 'RestaurantController@updateRequest');
        $api->get('restaurant/change-status/{requestId}', 'RestaurantController@changeStatus');

        // Preregistration Routes
        // Added by Hamid Shafer, 2017-02-25
        $api->get('prereg', 'PreregistrationController@all');
        $api->get('prereg/districts', 'PreregistrationController@districts');
        $api->get('prereg/assignments', 'PreregistrationController@assignments'); 
        $api->get('prereg/user_turnover_status', 'PreregistrationController@userStatus');          
        $api->get('prereg/turnovers', 'PreregistrationController@turnovers');        
        $api->get('prereg/sumturnovers', 'PreregistrationController@sumturnovers');      

        $api->post('prereg/update_assign_dealer', 'PreregistrationController@updateDealerForAssignmet');   
        $api->post('prereg/update_assign_contract', 'PreregistrationController@updateContractForAssignmet');   
        $api->post('prereg/{user_id}', 'PreregistrationController@store');


//        Client Routes
         $api->get('client/opening-hours/{id}', 'ClientController@getRestaurantOpeningHours');
	
        $api->post('client/clientPayment', 'ClientController@sotreClient_payment');
	
	$api->get('client/menu-list/{currentLanguage}', 'ClientController@getMenuList');
        $api->get('client/ingredient-list/{currentLanguage}', 'ClientController@getIngredientList');
        $api->get('client/restaurant-list', 'ClientController@getRestaurantList');
        $api->get('client/restaurant-address/{restaurantId}', 'ClientController@getRestaurantAddress');
        $api->post('client/send-request', 'ClientController@sendRequest');
        $api->get('client/get-requests', 'ClientController@getRequests');
        $api->get('client/get-confirm-requests', 'ClientController@getConfirmRequests');
        $api->get('client/get-cancel-requests', 'ClientController@getCancelRequests');
        $api->get('client/get-past-requests', 'ClientController@getPastRequests');
        $api->post('client/cancel-request', 'ClientController@cancelRequest');
        $api->get('client/request-print/{lang}/{orderId}', 'ClientController@printRequest');
        $api->post('client/confirm-request', 'ClientController@confirmRequest');
        $api->get('client/change-status/{requestId}', 'ClientController@changeStatus');
        $api->get('client/count-missing-booking', 'ClientController@countMissingBooking');
        $api->get('client/current-user-currency', 'ClientController@currentUserCurrency');
        $api->get('client/count-unread-request', 'ClientController@countUnreadRequest');
	
	
        $api->post('client/getClient_payment', 'ClientController@getClient_payment');
        $api->post('client/getClient', 'ClientController@getClient');
        $api->post('client/getFirstMembers', 'ClientController@getFirstMembers');

        $api->post('getAllOrdersWithDetail', 'OrderDetailController@getAllOrdersWithDetail');
        $api->post('client/getPaiedEmail', 'ClientController@getPaiedEmail'); // Send Email to the server
        $api->post('getAllOrdersArray', 'OrderDetailController@getAllOrdersArray');
        // end remuneration

        $api->get('clients', 'ClientController@all');
        $api->put('client', 'ClientController@update');
        $api->delete('client/{clientId}', 'ClientController@delete');
        $api->post('client/friends', 'ClientController@addFriends'); // Add friends to your circle
        $api->get('client/friends', 'ClientController@getFriendsInMyCircle'); // Get friends in your circle
        $api->get('client/quizclient', 'ClientController@getQuizClient'); // Get Quiz Client Info
        $api->get('client/quizPrize', 'ClientController@getQuizPrize'); // Get Quiz Prize Info
        $api->get('client/updatelastcrossingtime', 'ClientController@updateLastCrossingTime'); // UpdateLastCrossingTime
        $api->post('client/sendEmail', 'ClientController@sendEmail'); // Send Email
        $api->post('client/quizclient', 'ClientController@addQuizClient'); // Get Quiz Client Info
        $api->get('client/quizsetting', 'ClientController@getQuizSetting'); // Get quizSetting
        $api->get('client/question/{lang}', 'ClientController@getQuestion'); // Get Questions
        $api->get('client/circles', 'ClientController@getFriendsFromOtherCircle'); // Get friends from other circle
        $api->post('client/respond', 'ClientController@respond'); // Respond to a friend request
        $api->get('client/requests', 'ClientController@getFriendRequests'); // Get friend requests
        $api->get('client/sent_requests', 'ClientController@getSentFriendRequests'); // Get Sent Friend Requests
        $api->get('client/{clientId}', 'ClientController@item');
        $api->get('client', 'ClientController@getCurrentClient');

//        Menu Lists (there is a copy of this above without auth - needed for search)
//        $api->post('menu_lists', 'MenuListController@all');

       // Photo Routes
        $api->post('photo/{item_id}/{item_type}', 'PhotoController@store');
        $api->post('photo/update', 'PhotoController@update');
//        $api->delete('photo/{photo_id}', 'PhotoController@delete');
        $api->post('photo/url', 'PhotoController@deleteByUrl');

//        Order Routes
        $api->post('orders_detail', 'OrderDetailController@store');
        $api->put('orders_detail', 'OrderDetailController@updateOrdersDetail');
        $api->put('orders', 'OrderDetailController@updateOrders');
        $api->get('orders/{orderId}', 'OrderDetailController@getOrder');
        $api->get('get_orders/{orderId}', 'OrderDetailController@getOrderForDashboard');
        $api->post('order', 'OrderDetailController@update');
        $api->get('orders_detail/{restaurantId}', 'OrderDetailController@getOrderDetails');
        $api->get('tables/{restaurantId}', 'OrderDetailController@getTables');
        $api->get('enable_discount/{restaurantId}', 'OrderDetailController@getEnableDiscount');
        $api->get('orders', 'OrderDetailController@getOrders');
        $api->delete('order/{orderId}', 'OrderDetailController@deleteOrder');
        $api->delete('orders_detail/{orderDetailId}', 'OrderDetailController@deleteOrderDetail');
        $api->get('restaurant_menu', 'OrderDetailController@getRestaurantMenu');
        // rating routes
        $api->post('order/rate', 'OrderController@rateOrder');

        
        $api->get('orders_by_status', 'OrderDetailController@getOrdersByStatus');
        $api->get('orders_detail_by_status/{orderId}', 'OrderDetailController@getOrdersDetailByStatus');
        $api->get('cancel_order', 'OrderDetailController@cancelOrder');
        $api->delete('orders_detail/side_dish/{orderDetailId}', 'OrderDetailController@deleteSideDish');
        $api->get('print_order/{lang}/{orderId}', 'OrderDetailController@printOrder');
//        Menu Related
        $api->get('restaurant/{restaurantId}/menu_types', 'RestaurantController@getMenuTypes');
        $api->get('restaurant/{restaurantId}/menu_groups/{menuTypeId}', 'RestaurantController@getMenuGroups');
        $api->get('restaurant/{restaurantId}/menu_subgroups/{menuGroupId}', 'RestaurantController@getMenuSubGroups');
        $api->get('restaurant/{restuarantId}/menu_lists/{menuSubGroupId}', 'RestaurantController@getMenuLists');

        // patron
        $api->get('Allpatronage', 'OrderDetailController@getAllPatronage');
        $api->get('getActivePatronage', 'OrderDetailController@getActivePatronage');
        $api->get('getHistoryPatronage', 'OrderDetailController@getHistoryPatronage');
        $api->get('getBillingPatronage', 'OrderDetailController@getBillingPatronage');
        $api->get('getRestaurantType', 'OrderDetailController@getRestaurantType');
        $api->post('patron/activate', 'OrderDetailController@patronActivate');
        $api->post('patron/remove', 'OrderDetailController@patronRemove');
        $api->post('patron/sendAmount', 'OrderDetailController@sendAmount'); // Send Email
        
    });

    $api->get('free', function(){
        echo "Start";
        $exitCode = Artisan::call('cache:clear');
        echo "1 - " . $exitCode;
    });



});
