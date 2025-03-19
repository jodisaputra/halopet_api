<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\CountryController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

// Get all countries
Route::get('/countries', [CountryController::class, 'index']);

// Search countries
Route::get('/countries/search', [CountryController::class, 'search']);

// Get country by code
Route::get('/countries/code/{code}', [CountryController::class, 'getByCode']);

// Get country by ID
Route::get('/countries/{id}', [CountryController::class, 'show']);


//auth controller
Route::prefix('auth')->group(function () {
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/google', [AuthController::class, 'handleGoogleLogin']);
    Route::post('/logout', [AuthController::class, 'logout'])->middleware('auth:api');
});


Route::middleware('jwt.auth')->group(function () {
    Route::prefix('auth')->group(function () {
        Route::get('/user', [AuthController::class, 'user']);
        Route::post('/refresh', [AuthController::class, 'refresh']);
        Route::post('/logout', [AuthController::class, 'logout']);
    });
});

