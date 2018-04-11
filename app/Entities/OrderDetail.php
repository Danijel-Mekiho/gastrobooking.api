<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

class OrderDetail extends Model
{
    public $table = "orders_detail";

    public $timestamps = false;
    protected $fillable = [
        "x_number", "price", "serve_at", "is_child", "status", "comment", "side_dish", "client_commission", "member_commission"
    ];

    public $primaryKey = "ID";

    public function requestParam()
    {
        return $this->hasOne(RequestParam::class, 'ID_orders_detail');
    }

    public function requestMenu()
    {
        return $this->belongsTo(RequestMenu::class, 'ID_request_menu');
    }
    
    public function menu_list(){
        return $this->belongsTo(MenuList::class, "ID_menu_list");
    }

    public function order(){
        return $this->belongsTo(Order::class, "ID_orders");
    }

    public function client()
    {
        return $this->belongsTo(Client::class, "ID_client");
    }

    public function scopeFilterByStatus($query, Request $request){
        if ($request->has("status")){
            $query->where('status', $request->status);
        }
    }

    public function sideDish()
    {
        return $this->hasMany(OrderDetail::class, 'side_dish', 'ID');
    }

    public function mainDish()
    {
        return $this->belongsTo(OrderDetail::class, 'side_dish', 'ID');
    }

    public function language()
    {
        return $this->belongsTo(Setting::class, 'currency', 'currency_short');
    }
}
