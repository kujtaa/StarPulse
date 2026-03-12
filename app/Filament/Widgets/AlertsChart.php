<?php

namespace App\Filament\Widgets;

use App\Models\AlertGroup;
use Filament\Widgets\ChartWidget;
use Illuminate\Support\Carbon;

class AlertsChart extends ChartWidget
{
    protected static ?string $heading = 'Alert Volume — Last 24 Hours';

    protected static ?int $sort = 2;

    protected int | string | array $columnSpan = 'full';

    protected function getType(): string
    {
        return 'bar';
    }

    protected function getData(): array
    {
        $orgId = auth()->user()->organization_id;
        $hours = collect(range(23, 0))->map(fn ($i) => Carbon::now()->subHours($i)->startOfHour());

        $counts = $hours->map(function (Carbon $hour) use ($orgId) {
            return AlertGroup::where('organization_id', $orgId)
                ->whereBetween('last_seen', [$hour, $hour->copy()->endOfHour()])
                ->count();
        });

        return [
            'datasets' => [
                [
                    'label' => 'Alerts',
                    'data' => $counts->values()->toArray(),
                    'backgroundColor' => 'rgba(6, 182, 212, 0.5)',
                    'borderColor' => 'rgb(6, 182, 212)',
                    'borderWidth' => 1,
                ],
            ],
            'labels' => $hours->map(fn (Carbon $h) => $h->format('H:i'))->values()->toArray(),
        ];
    }
}
