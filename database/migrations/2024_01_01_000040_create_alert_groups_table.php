<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('alert_groups', function (Blueprint $table) {
            $table->id();
            $table->foreignId('organization_id')->constrained()->cascadeOnDelete();
            $table->uuid('agent_id');
            $table->string('fingerprint', 16);
            $table->string('category');
            $table->string('severity');
            $table->string('title');
            $table->timestamp('first_seen');
            $table->timestamp('last_seen');
            $table->unsignedInteger('count')->default(1);
            $table->text('last_detail')->nullable();
            $table->json('last_data')->nullable();
            $table->string('hostname')->nullable();
            $table->timestamps();

            $table->foreign('agent_id')->references('id')->on('agents')->cascadeOnDelete();
            $table->unique(['agent_id', 'fingerprint']);
            $table->index(['organization_id', 'last_seen']);
            $table->index(['organization_id', 'severity']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('alert_groups');
    }
};
