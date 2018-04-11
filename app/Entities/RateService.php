<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

class RateService extends Model
{
    public $table = "rate_service";

    protected $fillable = [
        'tableset_rating', 'quick_rating', 'helpful_rating'
    ];
    
    public $primaryKey = "ID";

    public function order(){
        return $this->belongsTo(Order::class, "ID_orders");
    }
   
}
