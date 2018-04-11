<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;

class QuizPrize extends Model
{
    public $table = "quiz_prize";

    public $primaryKey = "ID";

    public $timestamps = false;

    public function order() {
        return $this->belongsTo('App\Entities\Order', 'ID_order', 'ID');
    }
}
