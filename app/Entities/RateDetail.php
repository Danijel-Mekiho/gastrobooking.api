<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

class RateDetail extends Model
{
    public $table = "rate_detail";


    public $primaryKey = "ID";

    public function order_detail(){
        return $this->belongsTo(OrderDetail::class, "ID_orders_detail");
    }

   
}
