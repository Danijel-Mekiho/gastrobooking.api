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
use App\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;


class ClientGroupRepository
{
    protected $userRepository;
    
    public function __construct(UserRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    public function item($clientGroupId){
        return ClientGroup::find($clientGroupId);
    }

    public function store($request, $user)
    {
        $friend_requests = $request->friends;
        $approve_values = ["N", "R", "Y"];
        for ($i = 0; $i < count($friend_requests); $i++){
            $client_group = ClientGroup::where(["ID_client" => $user->client->ID, "ID_grouped_client" => $friend_requests[$i]["id"]]);
            if ($client_group->count()){
                if ($client_group->whereNotIn("approved", $approve_values)->count()){
                    $client_group = $client_group->whereNotIn("approved", $approve_values)->first();
                    $client_group->approved = 'R';
                    $client_group->save();
                }
                return $user->client;
            }
            $client_group = new ClientGroup();
            $client_group->ID_client = $user->client->ID;
            $client_group->ID_grouped_client = $friend_requests[$i]["id"];
            $client_group->approved = 'R';
            $client_group->save();
        }
        return $user->client; // Return the current Client
    }

    public function getFriends($clientId, $approved = ""){
        $clientGroup = ClientGroup::on();
        if ($approved != ""){
            $clientGroup->where("approved", $approved);
        }
        $clientGroup = $clientGroup->where("ID_client", $clientId)->orWhere('ID_grouped_client', $clientId);

        return $clientGroup->get();  // Returns friends of the current client based on the value of the approved column status
    }

    public function getFriendRequests($clientId){
        return ClientGroup::where("ID_grouped_client", $clientId)->where("approved", 'R')->get();
    }

    public function getSentRequests($clientId){
        return ClientGroup::where(["ID_client" => $clientId, "approved" => 'R'])->get();
    }

    public function respond($clientId, $grouped_clientId, $response){
        $clientGroup = ClientGroup::where(["ID_grouped_client" => $clientId, "ID_client" => (int)$grouped_clientId])->first();
        if ($clientGroup){
            if ($response == "Del"){
                $clientGroup->delete();
                return $clientGroup;
            }
            $clientGroup->approved = $response;
            $clientGroup->save();
            return $clientGroup;
        }
        $clientGroup2 = ClientGroup::where(["ID_client" => $clientId, "ID_grouped_client" => (int)$grouped_clientId])->first();
        if ($response == "Del"){
            $clientGroup2->delete();
            return $clientGroup2;
        }
        $clientGroup2->approved = $response;
        $clientGroup2->save();
        return $clientGroup2;
    }

    public function getConnections($clientId){
        $connections = ClientGroup::where(["approved" => 'Y'])->where(["ID_client" => $clientId])
                        ->orWhere(["ID_grouped_client"=>$clientId])->count();
        return $connections;
    }

    public function getClientName($clientId){
        $user = Client::find($clientId);
        if ($user && $user->user){
            return $user->user->name;
        }
        return "Unknown";
    }

    public function getFriendsInMyCircle($clientId){
        $clientGroup = ClientGroup::where(["ID_client" => $clientId, "approved" => 'Y']);
        return $clientGroup->get();
    }


    public function getFriendsFromOtherCircle($clientId){
        $clientGroup = ClientGroup::where(["ID_grouped_client" => $clientId, "approved" => 'Y']);
        return $clientGroup->get();
    }

    public function getFirstParent($clientId){
        $clientGroup = ClientGroup::where(["ID_grouped_client" => $clientId, "approved" => 'Y']);
        return $clientGroup->first();
    }

    // remuneration

    public function getFirstMembers(){
        $user = app('Dingo\Api\Auth\Auth')->user();
        $clientId = $user->client->ID;
        $firstMember = [];
        $clientGroup = ClientGroup::on();
        $index = 0;
        $clientGroup = $clientGroup->where("ID_client", $clientId)->where("approved", 'Y')->get();
        for ($i = 0; $i < count($clientGroup); $i++){
            $memberParent = ClientGroup::where(["ID_grouped_client" => $clientGroup[$i]["ID_grouped_client"], "approved" => 'Y'])->orderBy("ID", 'asc')->first();
            if ($memberParent["ID_client"] == $clientGroup[$i]["ID_client"] ) {
                $firstMember[$index] = $memberParent["ID_grouped_client"];
                $index = $index + 1;
            }
        }
        return $firstMember;
    }

    public function getPrecedings($clientId, $ID){
        $clientGroup = ClientGroup::on();
        $precedings = $clientGroup->where("ID_grouped_client", $clientId)->where("approved", 'Y')->where("ID", "<", $ID)->count();
        return $precedings;
    }
}