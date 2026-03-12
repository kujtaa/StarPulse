<?php

namespace App\Filament\Widgets;

use App\Models\AlertGroup;
use Filament\Widgets\ChartWidget;

class SeverityChart extends ChartWidget
{
    protected static ?string $heading = 'By Severity';

    protected static ?int $sort = 3;

    protected function getType(): string
    {
        return 'doughnut';
    }

    protected function getData(): array
    {
        $orgId = auth()->user()->organization_id;

        $counts = collect(AlertGroup::SEVERITIES)->mapWithKeys(function ($severity) use ($orgId) {
            return [
                $severity => AlertGroup::where('organization_id', $orgId)
                    ->where('severity', $severity)
                    ->where('last_seen', '>=', now()->subDay())
                    ->count(),
            ];
        });

        return [
            'datasets' => [
                [
                    'data' => $counts->values()->toArray(),
                    'backgroundColor' => [
                        'rgb(239, 68, 68)',   // critical — red
                        'rgb(249, 115, 22)',  // high — orange
                        'rgb(234, 179, 8)',   // medium — yellow
                        'rgb(6, 182, 212)',   // low — cyan
                    ],
                ],
            ],
            'labels' => $counts->keys()->map(fn ($s) => ucfirst($s))->toArray(),
        ];
    }
}
