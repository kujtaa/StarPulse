<?php

namespace App\Filament\Resources;

use App\Filament\Resources\DeploymentAttemptResource\Pages;
use App\Models\DeploymentAttempt;
use Filament\Resources\Resource;
use Filament\Tables;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class DeploymentAttemptResource extends Resource
{
    protected static ?string $model = DeploymentAttempt::class;

    protected static ?string $navigationIcon = 'heroicon-o-document-text';

    protected static ?string $navigationGroup = 'Security';

    protected static ?string $modelLabel = 'Deploy Log';

    protected static ?string $pluralModelLabel = 'Deploy Logs';

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
                Tables\Columns\TextColumn::make('status')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'allowed' => 'success',
                        'blocked' => 'danger',
                        default => 'gray',
                    }),

                Tables\Columns\TextColumn::make('source')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'github' => 'gray',
                        'gitlab' => 'warning',
                        default => 'info',
                    }),

                Tables\Columns\TextColumn::make('action'),

                Tables\Columns\TextColumn::make('ref')
                    ->label('Branch / Tag'),

                Tables\Columns\TextColumn::make('ip')
                    ->label('IP'),

                Tables\Columns\TextColumn::make('created_at')
                    ->dateTime()
                    ->sortable(),
            ])
            ->defaultSort('created_at', 'desc');
    }

    public static function canCreate(): bool
    {
        return false;
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListDeploymentAttempts::route('/'),
        ];
    }
}
