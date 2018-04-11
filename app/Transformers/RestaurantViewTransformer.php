<?php

namespace App\Transformers;

use App\Entities\RestaurantView;
use League\Fractal\TransformerAbstract;

/**
 * Created by PhpStorm.
 * User: eagle
 * Date: 01/11/17
 * Time: 03:13 AM
 */
class RestaurantViewTransformer extends TransformerAbstract
{
    public function transform(RestaurantView $restaurantView)
    {
        return [
            'ID' => $restaurantView->ID,
            'ID_restaurant' => $restaurantView->ID_restaurant,
            'view_time' => $restaurantView->view_time,
            'IP' => $restaurantView->IP,
            'disp_type' => $restaurantView->disp_type,
        ];
    }

}