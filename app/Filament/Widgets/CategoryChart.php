<?php

namespace App\Filament\Widgets;

use App\Models\AlertGroup;
use Filament\Widgets\ChartWidget;

class CategoryChart extends ChartWidget
{
    protected static ?string $heading = 'By Category';

    protected static ?int $sort = 4;

    protected function getType(): string
    {
        return 'doughnut';
    }

    protected function getData(): array
    {
        $orgId = auth()->user()->organization_id;

        $counts = collect(AlertGroup::CATEGORIES)->mapWithKeys(function ($cat) use ($orgId) {
            return [
                $cat => AlertGroup::where('organization_id', $orgId)
                    ->where('category', $cat)
                    ->where('last_seen', '>=', now()->subDay())
                    ->count(),
            ];
        })->filter(fn ($v) => $v > 0);

        $colors = [
            'rgb(6, 182, 212)',
            'rgb(168, 85, 247)',
            'rgb(59, 130, 246)',
            'rgb(16, 185, 129)',
            'rgb(245, 158, 11)',
            'rgb(239, 68, 68)',
            'rgb(236, 72, 153)',
            'rgb(107, 114, 128)',
        ];

        return [
            'datasets' => [
                [
                    'data' => $counts->values()->toArray(),
                    'backgroundColor' => array_slice($colors, 0, $counts->count()),
                ],
            ],
            'labels' => $counts->keys()->map(fn ($c) => ucfirst($c))->toArray(),
        ];
    }
}
