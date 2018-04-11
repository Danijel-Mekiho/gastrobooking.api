<?php

namespace App\Entities;

use Illuminate\Database\Eloquent\Model;

class SyncServOwn extends Model
{
    //
    protected $table = "sync_serv_own";
    public $timestamps = false;
    protected $primaryKey = 'ID';
}
