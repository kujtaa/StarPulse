<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('telegram_configs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->unique()->constrained()->cascadeOnDelete();
            $table->string('bot_token')->nullable();
            $table->string('chat_id')->nullable();
            $table->boolean('enabled')->default(false);
            $table->boolean('notify_critical')->default(true);
            $table->boolean('notify_high')->default(true);
            $table->boolean('notify_medium')->default(false);
            $table->boolean('notify_offline')->default(true);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('telegram_configs');
    }
};
