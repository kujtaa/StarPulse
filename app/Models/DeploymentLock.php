<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class DeploymentLock extends Model
{
    protected $fillable = [
        'organization_id',
        'enabled',
        'lock_start',
        'lock_end',
        'timezone',
        'allowed_days',
        'webhook_secret',
    ];

    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'allowed_days' => 'array',
        ];
    }

    protected static function boot(): void
    {
        parent::boot();

        static::creating(function (DeploymentLock $lock) {
            if (empty($lock->webhook_secret)) {
                $lock->webhook_secret = Str::random(64);
            }
        });
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    /**
     * Determine if deployments are currently locked (outside the allowed window).
     */
    public function isLocked(): bool
    {
        if (! $this->enabled) {
            return false;
        }

        $tz = $this->timezone ?? 'UTC';
        $now = now($tz);

        if (! empty($this->allowed_days) && ! in_array($now->dayOfWeek, $this->allowed_days)) {
            return true;
        }

        if ($this->lock_start && $this->lock_end) {
            $start = $now->copy()->setTimeFromTimeString($this->lock_start);
            $end = $now->copy()->setTimeFromTimeString($this->lock_end);

            if ($start->lte($end)) {
                return $now->between($start, $end);
            }

            return $now->gte($start) || $now->lte($end);
        }

        return false;
    }
}
