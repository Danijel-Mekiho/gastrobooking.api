<?php
namespace App\Entities;

use Illuminate\Database\Eloquent\Model;

class RequestMenu extends Model
{
    public $table = "request_menu";

    public $primaryKey = "ID";

    public function requestIngredient()
    {
        return $this->hasMany(RequestIngredient::class, 'ID_request_menu', 'ID');
    }

}