<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;


class RestaurantClick extends Model
{
    
    public $table = "restaurant_click";
    
    protected $fillable = [
        'ID_restaurant', 'view_time', 'IP' , 'click_at'
    ];

    public $primaryKey = "ID";
    
    public $timestamps = false; 
}
