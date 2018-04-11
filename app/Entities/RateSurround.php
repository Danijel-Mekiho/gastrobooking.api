<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

class RateSurround extends Model
{
    public $table = "rate_surround";


    public $primaryKey = "ID";

    public function order(){
        return $this->belongsTo(Order::class, "ID_orders");
    }

   
}
