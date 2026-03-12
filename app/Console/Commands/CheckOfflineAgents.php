<?php

namespace App\Console\Commands;

use App\Models\Agent;
use App\Services\TelegramService;
use Illuminate\Console\Command;

class CheckOfflineAgents extends Command
{
    protected $signature = 'sentinel:check-offline';

    protected $description = 'Check for offline agents and send notifications';

    public function handle(): void
    {
        $threshold = now()->subSeconds(120);

        $offlineAgents = Agent::where('last_seen', '<', $threshold)
            ->where('offline_alerted', false)
            ->where('is_active', true)
            ->get();

        foreach ($offlineAgents as $agent) {
            $agent->update(['offline_alerted' => true]);

            TelegramService::notifyOffline(
                $agent->organization_id,
                $agent->hostname ?? 'unknown',
                $agent->id
            );

            $this->info("Agent offline: {$agent->hostname} ({$agent->id})");
        }

        $this->info("Checked. Found {$offlineAgents->count()} newly offline agents.");
    }
}
