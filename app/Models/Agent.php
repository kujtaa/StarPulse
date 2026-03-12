<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;

class Agent extends Model
{
    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'id',
        'organization_id',
        'hostname',
        'ip',
        'os_info',
        'agent_ver',
        'first_seen',
        'last_seen',
        'meta',
        'tags',
        'is_active',
        'offline_alerted',
    ];

    protected function casts(): array
    {
        return [
            'meta' => 'array',
            'first_seen' => 'datetime',
            'last_seen' => 'datetime',
            'is_active' => 'boolean',
            'offline_alerted' => 'boolean',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function alertGroups(): HasMany
    {
        return $this->hasMany(AlertGroup::class);
    }

    public function getIsOnlineAttribute(): bool
    {
        return $this->last_seen && $this->last_seen->greaterThan(Carbon::now()->subSeconds(120));
    }

    public function scopeOnline(Builder $query): Builder
    {
        return $query->where('last_seen', '>=', Carbon::now()->subSeconds(120));
    }

    public function scopeOffline(Builder $query): Builder
    {
        return $query->where(function (Builder $q) {
            $q->whereNull('last_seen')
              ->orWhere('last_seen', '<', Carbon::now()->subSeconds(120));
        });
    }
}
