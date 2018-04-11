<?php
namespace App\Entities;

use Illuminate\Database\Eloquent\Model;

class RequestIngredient extends Model
{
    public $table = "request_ingredient";

    public $primaryKey = "ID";

    public function ingredient()
    {
        return $this->belongsTo(Ingredient::class, 'ID_ingredient');
    }

    public function duplicate_of_ingredient()
    {
        return $this->belongsTo(RequestIngredient::class, 'ID', 'duplicate_of');
    }
}