<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

class RateMenu extends Model
{
    public $table = "rate_menu";


    public $primaryKey = "ID";

    public function order_detail(){
        return $this->belongsTo(OrderDetail::class, "ID_orders_detail");
    }

   
}
