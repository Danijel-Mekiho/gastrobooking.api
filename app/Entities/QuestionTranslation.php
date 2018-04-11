<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;

class QuestionTranslation extends Model
{
    public $table = "quiz_question_translations";

    public $primaryKey = "ID";
}
