<?php

namespace App\Filament\Widgets;

use App\Models\AlertGroup;
use Filament\Tables;
use Filament\Tables\Table;
use Filament\Widgets\TableWidget;

class RecentAlerts extends TableWidget
{
    protected static ?string $heading = 'Recent Critical & High Alerts';

    protected static ?int $sort = 5;

    protected int | string | array $columnSpan = 'full';

    public function table(Table $table): Table
    {
        return $table
            ->query(
                AlertGroup::query()
                    ->where('organization_id', auth()->user()->organization_id)
                    ->whereIn('severity', ['critical', 'high'])
                    ->orderByDesc('last_seen')
                    ->limit(10)
            )
            ->columns([
                Tables\Columns\TextColumn::make('severity')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'critical' => 'danger',
                        'high' => 'warning',
                        default => 'gray',
                    }),

                Tables\Columns\TextColumn::make('title')
                    ->limit(50),

                Tables\Columns\TextColumn::make('hostname'),

                Tables\Columns\TextColumn::make('count')
                    ->badge()
                    ->color('primary'),

                Tables\Columns\TextColumn::make('last_seen')
                    ->since(),
            ])
            ->paginated(false);
    }
}
