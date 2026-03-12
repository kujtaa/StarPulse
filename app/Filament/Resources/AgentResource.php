<?php

namespace App\Filament\Resources;

use App\Filament\Resources\AgentResource\Pages;
use App\Models\Agent;
use Filament\Infolists;
use Filament\Infolists\Infolist;
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
                Tables\Columns\TextColumn::make('status')
                    ->label('Status')
                    ->badge()
                    ->getStateUsing(fn (Agent $record): string => $record->status)
                    ->color(fn (string $state): string => match ($state) {
                        'Online' => 'success',
                        'Pending' => 'warning',
                        default => 'danger',
                    })
                    ->icon(fn (string $state): string => match ($state) {
                        'Online' => 'heroicon-o-check-circle',
                        'Pending' => 'heroicon-o-clock',
                        default => 'heroicon-o-x-circle',
                    }),

                Tables\Columns\TextColumn::make('hostname')
                    ->searchable()
                    ->sortable(),

                Tables\Columns\TextColumn::make('registered_address')
                    ->label('Address')
                    ->searchable()
                    ->toggleable(),

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
                        'pending' => 'Pending',
                    ])
                    ->query(function (Builder $query, array $data): Builder {
                        return match ($data['value']) {
                            'online' => $query->online(),
                            'offline' => $query->offline(),
                            'pending' => $query->pending(),
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
                Tables\Actions\ViewAction::make()
                    ->modalHeading(fn (Agent $record): string => $record->hostname ?? $record->registered_address ?? 'Server')
                    ->modalWidth('3xl')
                    ->infolist([
                        Infolists\Components\Section::make('Server Info')
                            ->columns(3)
                            ->schema([
                                Infolists\Components\TextEntry::make('status')
                                    ->badge()
                                    ->getStateUsing(fn (Agent $record): string => $record->status)
                                    ->color(fn (string $state): string => match ($state) {
                                        'Online' => 'success',
                                        'Pending' => 'warning',
                                        default => 'danger',
                                    }),
                                Infolists\Components\TextEntry::make('hostname')
                                    ->label('Hostname'),
                                Infolists\Components\TextEntry::make('ip')
                                    ->label('IP Address')
                                    ->placeholder('Not connected yet'),
                            ]),
                        Infolists\Components\Section::make('System Details')
                            ->columns(3)
                            ->schema([
                                Infolists\Components\TextEntry::make('os_info')
                                    ->label('Operating System')
                                    ->placeholder('Unknown'),
                                Infolists\Components\TextEntry::make('agent_ver')
                                    ->label('Agent Version')
                                    ->badge()
                                    ->placeholder('N/A'),
                                Infolists\Components\TextEntry::make('registered_address')
                                    ->label('Registered Address')
                                    ->placeholder('Direct install'),
                            ]),
                        Infolists\Components\Section::make('Activity')
                            ->columns(3)
                            ->schema([
                                Infolists\Components\TextEntry::make('first_seen')
                                    ->label('First Seen')
                                    ->dateTime()
                                    ->placeholder('Never'),
                                Infolists\Components\TextEntry::make('last_seen')
                                    ->label('Last Seen')
                                    ->since()
                                    ->placeholder('Never'),
                                Infolists\Components\TextEntry::make('tags')
                                    ->badge()
                                    ->separator(',')
                                    ->placeholder('No tags'),
                            ]),
                        Infolists\Components\Section::make('Recent Alerts')
                            ->icon('heroicon-o-bell-alert')
                            ->schema([
                                Infolists\Components\RepeatableEntry::make('alertGroups')
                                    ->hiddenLabel()
                                    ->columns(4)
                                    ->schema([
                                        Infolists\Components\TextEntry::make('severity')
                                            ->badge()
                                            ->color(fn (string $state): string => match ($state) {
                                                'critical' => 'danger',
                                                'high' => 'warning',
                                                'medium' => 'warning',
                                                default => 'info',
                                            }),
                                        Infolists\Components\TextEntry::make('title')
                                            ->columnSpan(2),
                                        Infolists\Components\TextEntry::make('last_seen')
                                            ->since(),
                                    ])
                                    ->placeholder('No alerts recorded for this server.'),
                            ]),
                    ]),
                Tables\Actions\DeleteAction::make(),
            ])
            ->emptyStateHeading('No servers yet')
            ->emptyStateDescription('Add your first server by installing the StarPulse agent.')
            ->emptyStateIcon('heroicon-o-server-stack')
            ->emptyStateActions([
                Tables\Actions\Action::make('addServer')
                    ->label('Add Server')
                    ->icon('heroicon-o-plus')
                    ->url(route('filament.admin.pages.install-agent')),
            ])
            ->poll('15s');
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListAgents::route('/'),
        ];
    }
}
