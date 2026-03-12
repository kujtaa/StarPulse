<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Str;

class Organization extends Model
{
    protected $fillable = [
        'name',
        'slug',
    ];

    protected static function boot(): void
    {
        parent::boot();

        static::creating(function (Organization $org) {
            if (empty($org->slug)) {
                $org->slug = Str::slug($org->name);
            }
        });
    }

    public function users(): HasMany
    {
        return $this->hasMany(User::class);
    }

    public function agents(): HasMany
    {
        return $this->hasMany(Agent::class);
    }

    public function apiTokens(): HasMany
    {
        return $this->hasMany(ApiToken::class);
    }

    public function alertGroups(): HasMany
    {
        return $this->hasMany(AlertGroup::class);
    }

    public function telegramConfig(): HasOne
    {
        return $this->hasOne(TelegramConfig::class);
    }

    public function deploymentLock(): HasOne
    {
        return $this->hasOne(DeploymentLock::class);
    }

    public function deploymentAttempts(): HasMany
    {
        return $this->hasMany(DeploymentAttempt::class);
    }
}
