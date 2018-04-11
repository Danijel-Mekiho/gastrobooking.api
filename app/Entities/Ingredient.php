<?php
namespace App\Entities;

use Illuminate\Database\Eloquent\Model;

class Ingredient extends Model
{
    public $table = "ingredient";
    public $primaryKey = "ID";
}