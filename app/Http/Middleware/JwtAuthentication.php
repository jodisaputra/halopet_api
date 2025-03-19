<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use App\Models\User;
use Symfony\Component\HttpFoundation\Response;

class JwtAuthentication
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // Ambil token dari header Authorization
        $token = $this->getTokenFromRequest($request);

        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthenticated - Token not provided'
            ], Response::HTTP_UNAUTHORIZED);
        }

        try {
            // Decode token menggunakan secret key dari config
            $key = config('app.key');
            $decoded = JWT::decode($token, new Key($key, 'HS256'));

            // Pastikan format token valid dan memiliki subject (user id)
            if (!isset($decoded->sub)) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Invalid token format'
                ], Response::HTTP_UNAUTHORIZED);
            }

            // Cari user berdasarkan ID dari token
            $user = User::find($decoded->sub);

            if (!$user) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'User not found'
                ], Response::HTTP_UNAUTHORIZED);
            }

            // Periksa apakah token sudah kadaluarsa
            if (isset($decoded->exp) && $decoded->exp < time()) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Token has expired'
                ], Response::HTTP_UNAUTHORIZED);
            }

            // Lampirkan user ke request untuk digunakan di controller
            $request->setUserResolver(function () use ($user) {
                return $user;
            });

            return $next($request);
        }
        catch (ExpiredException $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Token has expired'
            ], Response::HTTP_UNAUTHORIZED);
        }
        catch (SignatureInvalidException $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Token signature is invalid'
            ], Response::HTTP_UNAUTHORIZED);
        }
        catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Token is invalid',
                'error' => $e->getMessage()
            ], Response::HTTP_UNAUTHORIZED);
        }
    }

    /**
     * Get the token from the request header.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string|null
     */
    protected function getTokenFromRequest(Request $request)
    {
        // Cek header Authorization
        $header = $request->header('Authorization');

        if (!$header) {
            return null;
        }

        // Extract token dari format "Bearer {token}"
        if (preg_match('/Bearer\s+(.*)$/i', $header, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Generate a JWT token for the given user.
     *
     * @param  \App\Models\User  $user
     * @param  int  $expireTime  Time in seconds until the token expires (1 week by default)
     * @return string
     */
    public static function generateToken($user, $expireTime = 604800)
    {
        // Konfigurasi payload JWT
        $payload = [
            'iss' => config('app.url'),         // Issuer (application URL)
            'sub' => $user->id,                 // Subject (user ID)
            'iat' => time(),                    // Issued at time
            'exp' => time() + $expireTime,      // Expire time
            'user' => [                         // Additional user data
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
            ]
        ];

        // Gunakan secret key dari config
        $key = config('app.key');

        // Generate dan kembalikan token
        return JWT::encode($payload, $key, 'HS256');
    }

    /**
     * Decode and validate a JWT token.
     *
     * @param  string  $token
     * @return object|false  Decoded token payload or false if invalid
     */
    public static function validateToken($token)
    {
        try {
            $key = config('app.key');
            return JWT::decode($token, new Key($key, 'HS256'));
        } catch (\Exception $e) {
            return false;
        }
    }
}
