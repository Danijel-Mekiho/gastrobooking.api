<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

class RateSetting extends Model
{
    public $table = "rate_setting";

    protected $fillable = [ 'menu', 'service', 'surround', 'taste', 'amount', 'look', 'quick', 'laytable', 'helpful', 'pleasant', 'toilet', 'air' ];

    public $primaryKey = "ID";

 
}