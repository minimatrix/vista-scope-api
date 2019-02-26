<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Board extends Model
{
    protected $table = 'boards';
    protected $guarded = ['id'];

    public function owner()
    {
        return belongsTo('App\User');
    }
}
