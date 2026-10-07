<?php

namespace Alexusmai\LaravelFileManager;

use Alexusmai\LaravelFileManager\Middleware\FileManagerACL;
use Alexusmai\LaravelFileManager\Services\ACLService\ACLRepository;
use Alexusmai\LaravelFileManager\Services\ConfigService\ConfigRepository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;

class FileManagerServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        $this->warnIfUnprotected();

        // routes
        $this->loadRoutesFrom(__DIR__.'/routes.php');

        // views
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'file-manager');

        // publish config
        $this->publishes([
            __DIR__
            .'/../config/file-manager.php' => config_path('file-manager.php'),
        ], 'fm-config');

        // publish views
        $this->publishes([
            __DIR__
            .'/../resources/views' => resource_path('views/vendor/file-manager'),
        ], 'fm-views');

        // publish js and css files - vue-file-manager module
        $this->publishes([
            __DIR__
            .'/../resources/assets' => public_path('vendor/file-manager'),
        ], 'fm-assets');

        // publish migrations
        $this->publishes([
            __DIR__
            .'/../migrations' => database_path('migrations'),
        ], 'fm-migrations');
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/file-manager.php',
            'file-manager'
        );

        // Config Repository
        $this->app->bind(
            ConfigRepository::class,
            $this->app['config']['file-manager.configRepository']
        );

        // ACL Repository
        $this->app->bind(
            ACLRepository::class,
            $this->app->make(ConfigRepository::class)->getAclRepository()
        );

        // register ACL middleware
        $this->app['router']->aliasMiddleware('fm-acl', FileManagerACL::class);
    }

    /**
     * Cache key used to throttle the unprotected-install warning below
     * to at most once per day, instead of once per application boot.
     */
    protected const UNPROTECTED_WARNING_CACHE_KEY = 'laravel-file-manager::unprotected-install-warning';

    /**
     * The package ships with no authentication enforced by default -
     * only the "web" middleware group (session + CSRF) and ACL off.
     * Warn if nothing in the configured middleware stack looks like
     * an auth guard and ACL is disabled, since that combination
     * exposes every file-manager route (browse, upload, delete,
     * download) to unauthenticated users.
     *
     * This is a warning only - it does not block route registration,
     * since middleware names vary (auth, auth:sanctum, jwt.auth,
     * a custom guard, ...) and we can't reliably detect every case.
     *
     * boot() runs on *every* request and Artisan command for the
     * whole application (not just file-manager routes), so the
     * warning is throttled to once per day via the cache - logging it
     * unconditionally would spam the log on every single request on
     * exactly the installs most likely to have real traffic (public-
     * facing, unprotected ones).
     *
     * @return void
     */
    protected function warnIfUnprotected(): void
    {
        $config = $this->app->make(ConfigRepository::class);

        $hasAuthMiddleware = collect($config->getMiddleware())
            ->contains(fn ($middleware) => str_contains(
                strtolower((string) $middleware), 'auth'
            ));

        if ($hasAuthMiddleware || $config->getAcl()) {
            return;
        }

        try {
            if (Cache::has(self::UNPROTECTED_WARNING_CACHE_KEY)) {
                return;
            }

            Cache::put(self::UNPROTECTED_WARNING_CACHE_KEY, true, now()->addDay());
        } catch (\Throwable $exception) {
            // cache unavailable - fall through and log anyway rather
            // than silently losing the warning entirely
        }

        Log::warning(
            '[laravel-file-manager] No authentication middleware detected in '
            .'"file-manager.middleware" and ACL is disabled. The file manager '
            .'routes (browse, upload, delete, download, ...) are reachable by '
            .'unauthenticated users. Add an auth middleware (e.g. "auth") to '
            .'config/file-manager.php or enable the ACL mechanism.'
        );
    }
}
