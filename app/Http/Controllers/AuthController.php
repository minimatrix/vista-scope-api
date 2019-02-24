<?php

namespace App\Http\Controllers;

use App\User;
use App\Http\Resources\UserDetails as UserDetailsResource;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;
use Carbon\Carbon;
use DB;


use Laravel\Passport\Passport;

class AuthController extends Controller
{
    public function verifyUser(Request $request)
    {
        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $user = Auth::user();

            $token = $user->createToken( env('APP_TOKEN_NAME'));
            $tokenResult = $token->token;
            $tokenResult->expires_at = Carbon::now()->addMinutes(1);

            $token = $token->accessToken;

            $resetRequired = Carbon::now()->diffInDays($user->updated_at) > 30;
            return response()->json(['authorised' => true, 'user' => new UserDetailsResource($user), 'token' => $token, 'reset' => $resetRequired], 200);
        } else {
            return response()->json(['authorised' => false, 'token' => null], 401);
        }
    }

    public function getUserFromToken(Request $request)
    {
        $user = Auth::user();
        if(!empty($user)){
            $resetRequired = Carbon::now()->diffInDays($user->updated_at) > 30;
            return response()->json(['authorised' => true, 'user' => new UserDetailsResource($user), 'token' => $request->token, 'reset' => $resetRequired], 200);
        }else{
            return response()->json("Invalid Token", 401);
        }
    }

    public function registerUser(Request $request)
    {
        $data = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);

        return response()->json(['created' => true], 200);
    }

    public function forgotPassword(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|string|email',
        ]);

        // find user by email
        $user = User::where('email',$data['email'])->first();

        //if no users matching then return error
        if(!isset($user))
        {
            return response()->json(array(
                'code'      =>  400,
                'message'   =>  "No account was found for that email address"
            ), 415);
        }

        $token = hash_hmac('sha256', str_random(40), env('APP_KEY'));

        //check for user having an existing token if so delete it
        $hasTokens = DB::table('password_resets')->where('email',$data['email'])->first();

        if($hasTokens)
        {
            DB::table('password_resets')->where('email',$data['email'])->delete();
        }

        DB::table(config('auth.passwords.users.table'))->insert([
            'email' => $user->email,
            'token' => Hash::make($token),
            'created_at' => Carbon::now()
        ]);

        $user->sendPasswordResetNotification($token);
        return response()->json(['success' => true], 200);
    }

    public function reset(Request $request)
    {
        $this->validate($request, $this->rules(), $this->validationErrorMessages());

        // Here we will attempt to reset the user's password. If it is successful we
        // will update the password on an actual user model and persist it to the
        // database. Otherwise we will parse the error and return the response.
        $response = $this->broker()->reset(
            $this->credentials($request), function ($user, $password) {
                $this->resetPassword($user, $password);
            }
        );

        // If the password was successfully reset, we will redirect the user back to
        // the application's home authenticated view. If there is an error we can
        // redirect them back to where they came from with their error message.
          switch ($response) {
            case Password::PASSWORD_RESET:
                  return response()->json(array(
                    'code'      =>  200,
                    'message'   =>  "Your password was sucessfully reset"
                ), 200);
                break;
            case Password::INVALID_USER:
                 return response()->json(array(
                    'code'      =>  415,
                    'message'   =>  "The email address entered could not be found"
                ), 415);
                break;
            case Password::INVALID_PASSWORD:
                 return response()->json(array(
                    'code'      =>  415,
                    'message'   =>  "The new password entered was invalid, please try again"
                ), 415);
                break;
            case Password::INVALID_TOKEN:
                 return response()->json(array(
                    'code'      =>  415,
                    'message'   =>  "Password reset failed! The link may have expired. Please request a new password reset link"
                ), 415);
            break;
            default:
                 return response()->json(array(
                    'code'      =>  415,
                    'message'   =>  "Password reset failed! Please check that both passwords match and are longer than 6 characters"
                ), 415);
            break;

        }
    }

    /**
     * Get the password reset validation rules.
     *
     * @return array
     */
    protected function rules()
    {
        return [
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|confirmed|min:6',
        ];
    }

    /**
     * Get the password reset validation error messages.
     *
     * @return array
     */
    protected function validationErrorMessages()
    {
        return [
            'email'=>'The email supplied was invalid',
            'email.required'=>'you must enter an email address',
            'password.required' => 'You must enter a password',
            'password.confirmed' => 'The passwords entered must match',
            'token.required' => 'The security token is missing or invalid, please request a new password reset email'
        ];
    }

    /**
     * Get the password reset credentials from the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    protected function credentials(Request $request)
    {
        return $request->only(
            'email', 'password', 'password_confirmation', 'token'
        );
    }

    /**
     * Reset the given user's password.
     *
     * @param  \Illuminate\Contracts\Auth\CanResetPassword  $user
     * @param  string  $password
     * @return void
     */
    protected function resetPassword($user, $password)
    {
        $user->password = Hash::make($password);

        $user->setRememberToken(str_random(60));

        $user->save();

        event(new PasswordReset($user));

        $this->guard()->login($user);
    }

    /**
     * Get the response for a successful password reset.
     *
     * @param  string  $response
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    protected function sendResetResponse($response)
    {
       return response()->json(['password changed' => true], 200);
    }

    /**
     * Get the response for a failed password reset.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $response
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    protected function sendResetFailedResponse(Request $request, $response)
    {
        return response()->json(['failed to reset password' => trans($response)], 401);
    }

    /**
     * Get the broker to be used during password reset.
     *
     * @return \Illuminate\Contracts\Auth\PasswordBroker
     */
    public function broker()
    {
        return Password::broker();
    }

    /**
     * Get the guard to be used during password reset.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard()
    {
        return Auth::guard();
    }

}
