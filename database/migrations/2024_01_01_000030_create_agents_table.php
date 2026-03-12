<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('agents', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->string('hostname')->nullable();
            $table->string('ip', 45)->nullable();
            $table->string('os_info')->nullable();
            $table->string('agent_ver', 20)->nullable();
            $table->timestamp('first_seen')->nullable();
            $table->timestamp('last_seen')->nullable();
            $table->json('meta')->nullable();
            $table->string('tags')->nullable();
            $table->boolean('is_active')->default(true);
            $table->boolean('offline_alerted')->default(false);
            $table->timestamps();

            $table->index(['organization_id', 'last_seen']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('agents');
    }
};
