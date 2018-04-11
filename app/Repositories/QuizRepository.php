<?php
/**
 * Created by PhpStorm.
 * User: tOm_HydRa
 * Date: 9/10/16
 * Time: 12:06 PM
 */

namespace App\Repositories;


use App\Entities\QuestionTranslation;
use App\Entities\QuizSetting;
use App\Entities\Question;
use App\Entities\QuizClient;
use App\Entities\OrderDetail;
use App\Entities\QuizPrize;
use App\Entities\Setting;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use Carbon\Carbon;


class QuizRepository
{
    public function getQuizSetting($lang){
        $quiz = QuizSetting::where(["lang" => $lang]);
        return $quiz->first();
    }

    public function getQuestion($lang)
    {
        $user = app('Dingo\Api\Auth\Auth')->user();
        $clientId = $user->client->ID;

        $question = Question::leftJoin((new QuestionTranslation())->getTable() . ' AS qqt', function ($join) use($lang) {
            $join->on('qqt.ID_quiz_question', '=', 'quiz_question.ID')
                ->where('qqt.lang', '=', $lang);
        })
//            ->whereNotIn('quiz_question.ID', function($query) use($clientId) {
//                $query->select('quiz_client.ID_quiz_question')
//                    ->from((new QuizClient())->getTable())
//                    ->where(['quiz_client.ID_client' => $clientId]);
//            })
            ->select([
                'quiz_question.ID',
                'quiz_question.q_group',
                'quiz_question.q_photo',
                'quiz_question.q_right',
                'quiz_question.percentage',
                'quiz_question.active',
                'qqt.lang',
                'qqt.question',
                'qqt.a',
                'qqt.b',
                'qqt.c',
                'qqt.d',
                'qqt.note'
            ])
            ->orderByRaw("RAND()")
            ->take(1)
            ->first();

        return $question;
    }

    public function getQuizClient($clientId)
    {
        $languages = Setting::all()->pluck('lang', 'short_name')->toArray();

        foreach ($languages as $code => &$lang) {
            $quizClients = QuizClient::where(['ID_client' => $clientId, 'lang' => $lang])->get();

            if ($quizClients->isEmpty()) {
                $lang = [
                    'total_questions' => 0,
                    'right_answers' => 0,
                    'wrong_answers' => 0,
                    'unanswered_answers' => 0,
                    'percentage_discount' => 0,
                    'daily_percentage_discount' => 0,
                    'lastanswered' => Carbon::create(1970, 1, 1, 0, 0, 0),
                    'percentage_step' => 0
                ];
            } else {
                $total_questions = 0;
                $right_answers = 0;
                $wrong_answers = 0;
                $unanswered_answers = 0;
                $percentage_discount = 0;
                $daily_percentage_discount = 0;

                $quizClientLast = QuizClient::where(['ID_client' => $clientId, 'bonus' => 0, 'lang' => $lang])
                    ->orderBy('created_at', 'desc')
                    ->first();

                foreach ($quizClients as $quiz) {
                    $total_questions++;

                    if ($quiz->quiz_percentage != 0) {
                        $right_answers++;
                    } else if ($quiz->answer == 'x') {
                        $unanswered_answers++;
                    } else {
                        $wrong_answers++;
                    }

                    $percentage_discount += $quiz->quiz_percentage;

                    if ($quiz->bonus == 0) {
                        $daily_percentage_discount += $quiz->quiz_percentage;
                    }
                }

                if (!$quizClientLast) {
                    $lastAnswered = Carbon::create(1970, 1, 1, 0, 0, 0);
                } else {
                    $lastAnswered = $quizClientLast->answered;
                }

                $lang = [
                    'total_questions' => $total_questions,
                    'right_answers' => $right_answers,
                    'wrong_answers' => $wrong_answers,
                    'unanswered_answers' => $unanswered_answers,
                    'percentage_discount' => $percentage_discount,
                    'daily_percentage_discount' => $daily_percentage_discount,
                    'lastanswered' => $lastAnswered
                ];
            }
        }

        return $languages;
    }

	public function getQuizPrize(){
       	$user = app('Dingo\Api\Auth\Auth')->user();
        $clientId = $user->client->ID;

        $languages = Setting::all()->pluck('lang', 'short_name')->toArray();

        foreach ($languages as $code => &$lang) {
            $quizPrizes = QuizPrize::with(['order'])
                ->where(['ID_client' => $clientId, 'lang' => $lang])
                ->get();
            $lang = [];

            foreach ($quizPrizes as $prize) {
                $created_at = new Carbon($prize->order->created_at);
                $lang[] = [
                    'created_at' => $created_at->toDateTimeString(),
                    'percentage' => $prize->percentage,
                    'prize' => $prize->prize
                ];
            }
        }

        return $languages;
    }
    
    public function updateLastCrossingTime(){
//    	$user = app('Dingo\Api\Auth\Auth')->user();
//        $clientId = $user->client->ID;
//        $quizClient = QuizClient::where(["ID_client" => $clientId])->whereNotNull('percentage_step_update')->orderBy('created_at', 'desc')->first();
//        if(!$quizClient->percentage_step_update)
//        	$quizClient->percentage_step_update = 1;
//        else $quizClient->percentage_step_update ++;
//        $quizClient->save();
//        return $quizClient;
    }

    public function storeQuizClient($quizResult) {
    	$user = app('Dingo\Api\Auth\Auth')->user();
        $clientId = $user->client->ID;
        
    	$quizClient = new QuizClient();
    	if ($quizResult->has('ID_quiz')) {
            $quizClient->ID_quiz_question = $quizResult->ID_quiz;
            $quizClient->ID_client = $clientId;
            $quizClient->bonus = $quizResult->bonus;
            $quizClient->answer = $quizResult->answer;
            $quizClient->answered = $quizResult->answered;
            $quizClient->rate_difficulty = $quizResult->rate_difficulty;
            $quizClient->rate_quality = $quizResult->rate_quality;
            $quizClient->lang = $quizResult->lang;
            if ($quizResult->isRight == true) {
                $quizClient->quiz_percentage = $quizResult->percentage;
            }
            $quizClient->save();
        }

        return $quizClient;
    }
}
