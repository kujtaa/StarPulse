<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AlertGroup extends Model
{
    public const SEVERITIES = ['critical', 'high', 'medium', 'low'];

    public const CATEGORIES = [
        'auth',
        'network',
        'filesystem',
        'process',
        'package',
        'config',
        'resource',
        'malware',
    ];

    protected $fillable = [
        'organization_id',
        'agent_id',
        'fingerprint',
        'category',
        'severity',
        'title',
        'first_seen',
        'last_seen',
        'count',
        'last_detail',
        'last_data',
        'hostname',
    ];

    protected function casts(): array
    {
        return [
            'first_seen' => 'datetime',
            'last_seen' => 'datetime',
            'last_data' => 'array',
            'count' => 'integer',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class);
    }
}
