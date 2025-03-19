<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use App\Http\Middleware\JwtAuthentication;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        // Validasi input
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        // Buat user baru
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Generate token JWT
        $token = JwtAuthentication::generateToken($user);

        return response()->json([
            'status' => 'success',
            'message' => 'User registered successfully',
            'user' => $user,
            'token' => $token,
        ], 201);
    }

    public function login(Request $request)
    {
        // Validasi input
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        // Cek kredensial
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid credentials',
            ], 401);
        }

        $user = User::where('email', $request->email)->firstOrFail();
        $token = JwtAuthentication::generateToken($user);

        return response()->json([
            'status' => 'success',
            'message' => 'Login successful',
            'user' => $user,
            'token' => $token,
        ]);
    }

    public function handleGoogleLogin(Request $request)
    {
        // Validasi input
        $validator = Validator::make($request->all(), [
            'id_token' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        try {
            // Verifikasi token Google menggunakan Socialite
            $googleUser = Socialite::driver('google')
                ->stateless()
                ->userFromToken($request->id_token);

            // Cek apakah user sudah ada di database
            $user = User::where('email', $googleUser->email)->first();

            if (!$user) {
                // Buat user baru jika belum ada
                $user = User::create([
                    'name' => $googleUser->name,
                    'email' => $googleUser->email,
                    'google_id' => $googleUser->id,
                    'password' => Hash::make(Str::random(16)), // Password acak
                ]);
            } else {
                // Update google_id jika user sudah ada tetapi belum pernah login dengan Google
                if (empty($user->google_id)) {
                    $user->google_id = $googleUser->id;
                    $user->save();
                }
            }

            // Generate token JWT
            $token = JwtAuthentication::generateToken($user);

            return response()->json([
                'status' => 'success',
                'message' => 'Google login successful',
                'user' => $user,
                'token' => $token,
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Google token verification failed',
                'error' => $e->getMessage(),
            ], 401);
        }
    }

    /**
     * Get the authenticated user
     * Requires 'jwt.auth' middleware
     */
    public function user(Request $request)
    {
        // Pengguna sudah tersedia di $request->user() berkat middleware JwtAuthentication
        return response()->json([
            'status' => 'success',
            'user' => $request->user()
        ]);
    }

    public function logout(Request $request)
    {
        // Untuk API stateless dengan JWT, tidak perlu melakukan apa-apa di server
        // Token JWT disimpan di sisi client, client hanya perlu menghapus token

        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }

    /**
     * Refresh JWT token
     * Requires 'jwt.auth' middleware
     */
    public function refresh(Request $request)
    {
        // Buat token baru untuk user yang sedang login
        $token = JwtAuthentication::generateToken($request->user());

        return response()->json([
            'status' => 'success',
            'message' => 'Token refreshed successfully',
            'token' => $token
        ]);
    }
}
