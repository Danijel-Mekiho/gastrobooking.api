<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

class RateClient extends Model
{
    public $table = "rate_client";


    public $primaryKey = "ID";

    public function order(){
        return $this->belongsTo(Order::class, "ID_orders");
    }

    public function client()
    {
        return $this->belongsTo(Client::class, "ID_client");
    }

   
}
