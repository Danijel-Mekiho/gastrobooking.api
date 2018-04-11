<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;

class QuizClient extends Model
{
    public $table = "quiz_client";

    public $primaryKey = "ID";

    public function language()
    {
        return $this->belongsTo(Setting::class, 'lang', 'lang');
    }
}
