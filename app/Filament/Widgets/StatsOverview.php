<?php

namespace App\Filament\Widgets;

use App\Models\Agent;
use App\Models\AlertGroup;
use App\Models\DeploymentAttempt;
use Filament\Widgets\StatsOverviewWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class StatsOverview extends StatsOverviewWidget
{
    protected static ?int $sort = 1;

    protected function getStats(): array
    {
        $orgId = auth()->user()->organization_id;

        $alerts24h = AlertGroup::where('organization_id', $orgId)
            ->where('last_seen', '>=', now()->subDay())
            ->count();

        $criticalAlerts = AlertGroup::where('organization_id', $orgId)
            ->where('severity', 'critical')
            ->where('last_seen', '>=', now()->subDay())
            ->count();

        $totalAgents = Agent::where('organization_id', $orgId)->count();
        $onlineAgents = Agent::where('organization_id', $orgId)->online()->count();

        $blockedDeploys = DeploymentAttempt::where('organization_id', $orgId)
            ->where('status', 'blocked')
            ->where('created_at', '>=', now()->subDay())
            ->count();

        return [
            Stat::make('Total Alerts (24h)', $alerts24h)
                ->description('Active alert groups')
                ->icon('heroicon-o-bell-alert')
                ->color('warning'),

            Stat::make('Critical Alerts', $criticalAlerts)
                ->description('Last 24 hours')
                ->icon('heroicon-o-exclamation-triangle')
                ->color('danger'),

            Stat::make('Servers Online', "{$onlineAgents} / {$totalAgents}")
                ->description($totalAgents > 0 ? round(($onlineAgents / $totalAgents) * 100) . '% online' : 'No servers')
                ->icon('heroicon-o-server-stack')
                ->color($onlineAgents === $totalAgents ? 'success' : 'warning'),

            Stat::make('Deploy Blocks (24h)', $blockedDeploys)
                ->description('Blocked deployments')
                ->icon('heroicon-o-shield-exclamation')
                ->color($blockedDeploys > 0 ? 'danger' : 'success'),
        ];
    }
}
