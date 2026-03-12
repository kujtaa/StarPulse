<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class TelegramConfig extends Model
{
    protected $fillable = [
        'organization_id',
        'bot_token',
        'chat_id',
        'enabled',
        'notify_critical',
        'notify_high',
        'notify_medium',
        'notify_offline',
    ];

    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'notify_critical' => 'boolean',
            'notify_high' => 'boolean',
            'notify_medium' => 'boolean',
            'notify_offline' => 'boolean',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }
}
