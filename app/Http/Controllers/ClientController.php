<?php

namespace App\Http\Controllers;

use App\Entities\Setting;
use App\Repositories\ClientGroupRepository;
use App\Repositories\QuizRepository;
use App\Repositories\ClientPaymentRepository;
use App\Transformers\ClientGroupTransformer;
use App\Transformers\ClientRequestTransformer;
use App\Transformers\ClientTransformer;
use App\Transformers\ClientTransformerSmall;
use App\Transformers\NewClientGroupTransformer;
use App\Transformers\UserTransformer;
use App\Transformers\QuizSettingTransformer;
use App\Transformers\QuestionTransformer;
use App\Transformers\QuizClientTransformer;
use App\User;
use Dingo\Api\Routing\Helpers;
use Illuminate\Http\Request;
use App\Repositories\ClientRepository;
use App\Repositories\MenuListRepository;
use App\Repositories\RestaurantRepository;

use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Mail;
use App\Jobs\SendReminderEmail;

use App\Transformers\AllOrderTransformer;
use App\Entities\ClientGroup;
use App\Entities\Client;
use App\Entities\Quiz;
use App\Entities\RequestMenu;
use App\Entities\Order;
use App\Entities\OrderDetail;
use App\Entities\MealRequest;
use App\Entities\RequestIngredient;
use View;

class ClientController extends Controller
{
    use Helpers;
    protected $clientRepository;
    protected $clientGroupRepository;
    protected $quizRepository;
    protected $menuListRepository;
    protected $restaurantRepository;
    public $perPage = 5;

    public function __construct(ClientRepository $clientRepository, ClientGroupRepository $clientGroupRepository, QuizRepository $quizRepository, ClientPaymentRepository $clientPaymentRepository, MenuListRepository $menuListRepository, RestaurantRepository $restaurantRepository)
    {
        $this->clientRepository = $clientRepository;
        $this->clientPaymentRepository = $clientPaymentRepository;
        $this->clientGroupRepository = $clientGroupRepository;
        $this->quizRepository = $quizRepository;
        $this->menuListRepository = $menuListRepository;
        $this->restaurantRepository = $restaurantRepository;
    }

    public function item($clientId){
        $client = $this->clientRepository->item($clientId);
        $response = $this->response->item($client, new ClientTransformer());
        return $response;
    }

    public function store(Request $request){
        app()->setLocale($request->input('lang', 'en'));
        $user = $this->clientRepository->store($request);
        if (!$user){
            return ["error" => "User already exists!"];
        }
        $this->sendEmailReminder($user);
        $response = $this->response->item($user, new UserTransformer());
        return $response;
    }

    public function update(Request $request){
        $client = $this->clientRepository->update($request);
        $response = $this->response->item($client, new ClientTransformer());
        return $response;
    }

    public function delete(){
        $client = $this->clientRepository->delete();
        $response = $this->response->item($client, new ClientTransformer());
        return $response;
    }

    public function all(Request $request){
        $clients = $this->clientRepository->all($request);
        $response = $this->response->collection($clients, new ClientTransformerSmall());
        return $response;
    }

    public function addFriends(Request $request){
        $user = app('Dingo\Api\Auth\Auth')->user();
        $friends = $this->clientGroupRepository->store($request, $user);
        $response = $this->response->item($friends, new ClientTransformerSmall());
        return $response;
    }

    public function getFriends(){
        $user = app('Dingo\Api\Auth\Auth')->user();
        $friends = $this->clientGroupRepository->getFriends($user->client->ID, 'Y');
        if ($friends){
            return $this->response->collection($friends, new ClientGroupTransformer($this->clientGroupRepository));
        }
        return ["error" => "No friends found!"];
    }

    public function getOtherFriends(){
        $user = app('Dingo\Api\Auth\Auth')->user();
        $friends = $this->clientGroupRepository->getFriends($user->client->ID, 'Y');
        if ($friends){
            return $this->response->collection($friends, new ClientGroupTransformer($this->clientGroupRepository));
        }
        return ["error" => "No friends found!"];
    }

    public function getFriendsInMyCircle(){
        $user = app('Dingo\Api\Auth\Auth')->user();
        $friends = $this->clientGroupRepository->getFriendsInMyCircle($user->client->ID);
        if ($friends && count($friends)){
            return $this->response->collection($friends, new NewClientGroupTransformer($this->clientGroupRepository, true));
        }
        return ["error" => "No friends found!"];
    }

    public function getQuizSetting(){
        // $user = app('Dingo\Api\Auth\Auth')->user();
        // $lang = Client::where("ID", $user->client->ID)->first()->lang;
        // if(!$lang) $lang = "CZE";
        // else if ($lang != "CZE" && $lang != "ENG") $lang = "CZE";
        //
        // $quizSetting = $this->quizRepository->getQuizSetting($lang);
        // if($quizSetting && count($quizSetting)) {
        //     return $this->response->item($quizSetting, new QuizSettingTransformer());
        // }
        //return ["error" => "No Quiz found!"];
        $languages = Setting::all()->pluck('lang', 'short_name')->toArray();

        foreach ($languages as $code => &$lang) {
            $lang = $this->quizRepository->getQuizSetting($lang);
        }

        return $this->response->array($languages, new QuizSettingTransformer());
    }

    public function getQuestion($lang = 'ENG') {
        $question = $this->quizRepository->getQuestion($lang);
        if($question && !is_null($question->question)) {
            return $this->response->item($question, new QuestionTransformer());
        }
        return ["error" => "No question Data!"];
    }

    public function getQuizClient() {
        $user = app('Dingo\Api\Auth\Auth')->user();
        $quizClient = $this->quizRepository->getQuizClient($user->client->ID);
        return $quizClient;
    }

    public function updateLastCrossingTime(){
        return $this->quizRepository->updateLastCrossingTime();
    }

    public function getQuizPrize(){
        return $this->quizRepository->getQuizPrize();
    }

    public function sendEmail(Request $request){
        //$currentUserName = $this->clientRepository->getUserName();

        $headers = "MIME-Version: 1.0" . "\r\n";
        $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";

        // More headers
        $headers .= "From: $request->from" . "\r\n";
        $headers .= 'Cc: quiz@gastro-booking.com' . "\r\n";

        $result0 = mail('quiz@gastro-booking.com','Quiz message', $request->input('content'),$headers);

        $result = $result0 ? "Message sent. Thank you." : "Sorry. Message send failed.";
        return $result;
    }

    public function addQuizClient(Request $request) {
        $quizClient = $this->quizRepository->storeQuizClient($request);
        $response = $this->response->item($quizClient, new QuizClientTransformer());
        return $response;
    }

    public function getFriendsFromOtherCircle(){
        $user = app('Dingo\Api\Auth\Auth')->user();
        $friends = $this->clientGroupRepository->getFriendsFromOtherCircle($user->client->ID);
        if ($friends && count($friends)){
            return $this->response->collection($friends, new NewClientGroupTransformer($this->clientGroupRepository, false));
        }
        return ["error" => "No friends found!"];
    }

    public function getFriendRequests(){
        $user = app('Dingo\Api\Auth\Auth')->user();
        $friends = $this->clientGroupRepository->getFriendRequests($user->client->ID);
        if ($friends){
            return $this->response->collection($friends, new ClientRequestTransformer($this->clientGroupRepository));
        }
        return ["error" => "No friend Requests found!"];
    }

    public function getSentFriendRequests(){
        $user = app('Dingo\Api\Auth\Auth')->user();
        $friends = $this->clientGroupRepository->getSentRequests($user->client->ID);
        if ($friends){
            return $this->response->collection($friends, new ClientGroupTransformer($this->clientGroupRepository));
        }
        return ["error" => "No sent friend requests found!"];
    }

    public function respond(Request $request){
        if ($request->has("response")){
            $client = app('Dingo\Api\Auth\Auth')->user()->client;
            $client_group = $this->clientGroupRepository->respond($client->ID, $request->response["ID_grouped_client"], $request->response["response"]);
            if ($client_group){
                return $this->response->item($client_group, new ClientGroupTransformer($this->clientGroupRepository));
            }
            return ["error" => "No record found!"];
        }
    }

    public function sendEmailReminder(User $user)
    {
        Mail::send('emails.client', ['user' => $user], function ($m) use($user){
            $m->from('cesko@gastro-booking.com', Lang::get("main.MAIL.GASTRO_BOOKING"));
            $m->to($user->email, $user->name)->subject(Lang::get("main.MAIL.REGISTRATION_SUCCESSFUL"));
        });

        return ['message' => "Email sent"];
    }

    public function getCurrentClient(){
        $client = app('Dingo\Api\Auth\Auth')->user()->client;
        $clientTransformer = new ClientTransformer();
        return array("data" => $clientTransformer->transform($client));
    }

    public function getMenuList($currentLanguage){
        return $this->menuListRepository->getMenuList($currentLanguage);
    }

    public function getIngredientList($currentLanguage){
         return $this->clientRepository->getIngredients($currentLanguage);
    }
    
    public function getRestaurantList(){
        return $this->restaurantRepository->getRestaurantList();
    }

    public function getRestaurantAddress($restaurantId){
        return $this->restaurantRepository->getRestaurantAddress($restaurantId);
    }

    public function sendRequest(Request $request) {
        return $this->clientRepository->sendRequest($request);
    }

    public function confirmRequest(Request $request) {
        return $this->clientRepository->confirmRequest($request);
    }

    public function getRequests(){
        $status = 'N';
        return $this->clientRepository->getRequests($status);
    }
    public function getConfirmRequests(){
        $status = 'C';
        return $this->clientRepository->getRequests($status);
    }
    public function getCancelRequests(){
        $status = 'CA';
        return $this->clientRepository->getRequests($status);
    }

    public function getPastRequests(){
        return $this->clientRepository->getPastRequests();
    }

    public function cancelRequest(Request $request){
        return $this->clientRepository->cancelRequest($request);
    }

    public function printRequest(Request $request, $lang, $orderId) {
        app()->setLocale($lang ?: 'en');
        $render_data = $this->clientRepository->getPrintData($request, $orderId);
        $view = View::make('emails.requestMeal.request_new_print', $render_data);
        $contents = $view->render();
        return $contents;
    }

    public function changeStatus($request_id){
        return $this->clientRepository->changeStatus($request_id);
    }

    public function countMissingBooking() {
        return $this->clientRepository->countMissingBooking();
    }

    public function currentUserCurrency() {
        return $this->clientRepository->currentUserCurrency();
    }

    public function countUnreadRequest() {
        return $this->clientRepository->countUnreadRequest();
    }

    public function getRestaurantOpeningHours($ID) {
        return $this->clientRepository->getRestaurantOpeningHours($ID);
    }

    public function sotreClient_payment(Request $request){
        $user = $this->clientPaymentRepository->store($request);
        // $response = $this->response->item($user, new UserTransformer());
        return $user;
    }
    public function getClient_payment() {
        $user = $this->clientPaymentRepository->get();
        return $user;
    }

    public function getClient(Request $request){
        $user = $this->clientRepository->getClient($request);
        return $user;
    }
    public function getFirstMembers(){
        $user = $this->clientGroupRepository->getFirstMembers();
        return ["data" => $user];
    }

    public function getPaiedEmail(Request $request){
        $user = app('Dingo\Api\Auth\Auth')->user();
        $result0 = Mail::send('emails.payment', ['user' => $request], function ($m) use($user){
            $m->from('cesko@gastro-booking.com', "Gastro Billing");
            $m->to('patron@gastro-booking.com', $user->name)->subject('CZE - Client payment request');
        });
        $result = $result0 ? "Message sent. Thank you." : "Sorry. Message send failed.";
        return $result;
    }
}
