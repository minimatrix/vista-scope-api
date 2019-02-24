<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
 */
Route::post('auth/verify', 'AuthController@verifyUser');
Route::post('auth/register', 'AuthController@registerUser');

Route::middleware('api')->post('auth/forgot-password', 'AuthController@forgotPassword');
Route::middleware('api')->post('auth/password-reset', 'AuthController@reset')->name('password.reset');

Route::prefix('public')->name('public.')->middleware('client')->group(function () {
   // external non-auth routes will go here
});

Route::group(['middleware' => 'auth:api'], function () { 
    // Auth
    Route::post('auth/verify/token', 'AuthController@getUserFromToken');

    // Users
    Route::get('users/search', 'UserController@search');
    Route::get('users/list', 'UserController@list');
    Route::put('users/{user}/password', 'UserController@changePassword');
    Route::apiResource('users', 'UserController');
});
