<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class ApiToken extends Model
{
    protected $fillable = [
        'organization_id',
        'token',
        'label',
    ];

    protected static function boot(): void
    {
        parent::boot();

        static::creating(function (ApiToken $token) {
            if (empty($token->token)) {
                $token->token = Str::random(64);
            }
        });
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }
}
