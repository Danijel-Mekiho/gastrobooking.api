<?php
namespace App\Entities;

use Illuminate\Database\Eloquent\Model;

class MealRequest extends Model
{
    public $table = "requests";

    public $primaryKey = "ID";

    public function orders(){
        return $this->belongsTo(Order::class, "ID_orders");
    }

    /* public function restaurant_orders($query, Request $request)
    {
            $query->whereHas("photos", function($query){
                return $query->where("item_type", "garden");
            
        });
    }*/

     public function restaurant_orders(){
        return $this->belongsTo(Restaurant::class, "ID_restaurant"); // or App\Product or any namespace you use
	    
    }

}