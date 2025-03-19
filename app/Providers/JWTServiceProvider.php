<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Auth;
use App\Services\JWTGuard;

class JWTServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        Auth::extend('jwt', function ($app, $name, array $config) {
            return new JWTGuard(
                Auth::createUserProvider($config['provider']),
                $app['request']
            );
        });
    }
}
