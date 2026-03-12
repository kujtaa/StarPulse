<?php

namespace App\Filament\Resources;

use App\Filament\Resources\AlertGroupResource\Pages;
use App\Models\Agent;
use App\Models\AlertGroup;
use Filament\Resources\Resource;
use Filament\Tables;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class AlertGroupResource extends Resource
{
    protected static ?string $model = AlertGroup::class;

    protected static ?string $navigationIcon = 'heroicon-o-bell-alert';

    protected static ?string $navigationGroup = 'Monitoring';

    protected static ?string $modelLabel = 'Alert';

    protected static ?string $pluralModelLabel = 'Alerts';

    protected static ?int $navigationSort = 2;

    public static function getEloquentQuery(): Builder
    {
        return parent::getEloquentQuery()
            ->where('organization_id', auth()->user()->organization_id);
    }

    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                Tables\Columns\TextColumn::make('severity')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'critical' => 'danger',
                        'high' => 'warning',
                        'medium' => 'warning',
                        'low' => 'info',
                        default => 'gray',
                    })
                    ->sortable(),

                Tables\Columns\TextColumn::make('category')
                    ->badge()
                    ->searchable(),

                Tables\Columns\TextColumn::make('title')
                    ->searchable()
                    ->wrap()
                    ->limit(50),

                Tables\Columns\TextColumn::make('hostname')
                    ->searchable(),

                Tables\Columns\TextColumn::make('count')
                    ->numeric()
                    ->sortable()
                    ->badge()
                    ->color('primary'),

                Tables\Columns\TextColumn::make('last_seen')
                    ->since()
                    ->sortable(),

                Tables\Columns\TextColumn::make('last_detail')
                    ->toggleable(isToggledHiddenByDefault: true)
                    ->limit(60),
            ])
            ->defaultSort('last_seen', 'desc')
            ->filters([
                Tables\Filters\SelectFilter::make('severity')
                    ->options(array_combine(AlertGroup::SEVERITIES, array_map('ucfirst', AlertGroup::SEVERITIES))),

                Tables\Filters\SelectFilter::make('category')
                    ->options(array_combine(AlertGroup::CATEGORIES, array_map('ucfirst', AlertGroup::CATEGORIES))),

                Tables\Filters\SelectFilter::make('agent_id')
                    ->label('Server')
                    ->options(fn (): array => Agent::query()
                        ->where('organization_id', auth()->user()->organization_id)
                        ->pluck('hostname', 'id')
                        ->toArray()
                    ),

                Tables\Filters\SelectFilter::make('time_range')
                    ->options([
                        '24h' => 'Last 24 Hours',
                        '7d' => 'Last 7 Days',
                        '30d' => 'Last 30 Days',
                    ])
                    ->query(function (Builder $query, array $data): Builder {
                        return match ($data['value']) {
                            '24h' => $query->where('last_seen', '>=', now()->subDay()),
                            '7d' => $query->where('last_seen', '>=', now()->subDays(7)),
                            '30d' => $query->where('last_seen', '>=', now()->subDays(30)),
                            default => $query,
                        };
                    }),
            ]);
    }

    public static function canCreate(): bool
    {
        return false;
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListAlertGroups::route('/'),
        ];
    }
}
