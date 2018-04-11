<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;


class RestaurantView extends Model
{
    
    public $table = "restaurant_view";
    
    protected $fillable = [
        'ID_restaurant', 'view_time', 'IP' , 'disp_type'
    ];

    public $primaryKey = "ID";

    public $timestamps = false; 
}
