<?php
namespace App\Entities;

use Illuminate\Database\Eloquent\Model;

class RequestParam extends Model
{
    public $table = "request_params";

    public $primaryKey = "ID";

 
    public function order_detail()
    {
        return $this->belongsTo(OrderDetail::class, 'ID_orders_detail');
    }

}