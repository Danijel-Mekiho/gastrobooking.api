<?php

namespace App\Transformers;

use App\Entities\RestaurantClick;
use League\Fractal\TransformerAbstract;

/**
 * Created by PhpStorm.
 * User: eagle
 * Date: 01/11/17
 * Time: 03:13 AM
 */
class RestaurantClickTransformer extends TransformerAbstract
{
    public function transform(RestaurantClick $restaurantClick)
    {
        return [
            'ID' => $restaurantClick->ID,
            'ID_restaurant' => $restaurantClick->ID_restaurant,
            'view_time' => $restaurantClick->view_time,
            'IP' => $restaurantClick->IP,
            'click_at' => $restaurantClick->click_at,
        ];
    }

}