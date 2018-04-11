<?php

namespace App\Transformers;

use App\Entities\Question;
use League\Fractal\TransformerAbstract;


class QuestionTransformer extends TransformerAbstract
{
    public function transform(Question $question)
    {
        return [
            'ID' => $question->ID,
            'q_group' => $question->q_group,
            'q_photo' => $question->q_photo,
            'lang' => $question->lang,
            'question' => $question->question,
            'a' => $question->a,
            'b' => $question->b,
            'c' => $question->c,
            'd' => $question->d,
            'q_right' => $question->q_right,
            'note' => $question->note,
            'percentage' => $question->percentage,
            'active' => $question->active
        ];
    }
}