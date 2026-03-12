<?php

namespace App\Filament\Resources;

use App\Filament\Resources\AgentResource\Pages;
use App\Models\Agent;
use Filament\Resources\Resource;
use Filament\Tables;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class AgentResource extends Resource
{
    protected static ?string $model = Agent::class;

    protected static ?string $navigationIcon = 'heroicon-o-server-stack';

    protected static ?string $navigationGroup = 'Monitoring';

    protected static ?string $modelLabel = 'Server';

    protected static ?string $pluralModelLabel = 'Servers';

    protected static ?int $navigationSort = 1;

    public static function getEloquentQuery(): Builder
    {
        return parent::getEloquentQuery()
            ->where('organization_id', auth()->user()->organization_id);
    }

    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                Tables\Columns\TextColumn::make('is_online')
                    ->label('Status')
                    ->badge()
                    ->getStateUsing(fn (Agent $record): string => $record->is_online ? 'Online' : 'Offline')
                    ->color(fn (string $state): string => $state === 'Online' ? 'success' : 'danger')
                    ->icon(fn (string $state): string => $state === 'Online' ? 'heroicon-o-check-circle' : 'heroicon-o-x-circle'),

                Tables\Columns\TextColumn::make('hostname')
                    ->searchable()
                    ->sortable(),

                Tables\Columns\TextColumn::make('ip')
                    ->label('IP')
                    ->searchable(),

                Tables\Columns\TextColumn::make('os_info')
                    ->label('OS')
                    ->toggleable(isToggledHiddenByDefault: true),

                Tables\Columns\TextColumn::make('agent_ver')
                    ->label('Version')
                    ->badge(),

                Tables\Columns\TextColumn::make('tags')
                    ->badge()
                    ->separator(','),

                Tables\Columns\TextColumn::make('last_seen')
                    ->since()
                    ->sortable(),

                Tables\Columns\TextColumn::make('alert_groups_count')
                    ->label('Alerts')
                    ->counts('alertGroups')
                    ->sortable()
                    ->badge()
                    ->color('warning'),
            ])
            ->defaultSort('last_seen', 'desc')
            ->filters([
                Tables\Filters\SelectFilter::make('status')
                    ->options([
                        'online' => 'Online',
                        'offline' => 'Offline',
                    ])
                    ->query(function (Builder $query, array $data): Builder {
                        return match ($data['value']) {
                            'online' => $query->online(),
                            'offline' => $query->offline(),
                            default => $query,
                        };
                    }),

                Tables\Filters\SelectFilter::make('tags')
                    ->options(fn (): array => Agent::query()
                        ->where('organization_id', auth()->user()->organization_id)
                        ->whereNotNull('tags')
                        ->pluck('tags')
                        ->flatMap(fn ($t) => explode(',', $t))
                        ->map(fn ($t) => trim($t))
                        ->unique()
                        ->filter()
                        ->mapWithKeys(fn ($t) => [$t => $t])
                        ->toArray()
                    )
                    ->query(fn (Builder $query, array $data): Builder => filled($data['value'])
                        ? $query->where('tags', 'like', "%{$data['value']}%")
                        : $query
                    ),
            ])
            ->actions([
                Tables\Actions\ViewAction::make(),
            ]);
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListAgents::route('/'),
        ];
    }
}
