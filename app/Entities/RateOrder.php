<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

class RateOrder extends Model
{
    public $table = "rate_order";

    protected $fillable = [
        'menu_rating', 'service_rating', 'surround_rating'
    ];
    
    public $primaryKey = "ID";

    public function order(){
        return $this->belongsTo(Order::class, "ID_orders");
    }

   
}
