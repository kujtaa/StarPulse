<?php

namespace App\Filament\Resources;

use App\Filament\Resources\ApiTokenResource\Pages;
use App\Models\ApiToken;
use Filament\Forms;
use Filament\Forms\Form;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Tables;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class ApiTokenResource extends Resource
{
    protected static ?string $model = ApiToken::class;

    protected static ?string $navigationIcon = 'heroicon-o-key';

    protected static ?string $navigationGroup = 'Settings';

    protected static ?string $modelLabel = 'API Token';

    protected static ?string $pluralModelLabel = 'API Tokens';

    protected static ?int $navigationSort = 1;

    public static function getEloquentQuery(): Builder
    {
        return parent::getEloquentQuery()
            ->where('organization_id', auth()->user()->organization_id);
    }

    public static function form(Form $form): Form
    {
        return $form
            ->schema([
                Forms\Components\TextInput::make('label')
                    ->required()
                    ->maxLength(255),
            ]);
    }

    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                Tables\Columns\TextColumn::make('label')
                    ->searchable(),

                Tables\Columns\TextColumn::make('token')
                    ->formatStateUsing(function (string $state): string {
                        if (strlen($state) <= 12) {
                            return $state;
                        }
                        return substr($state, 0, 8) . '...' . substr($state, -4);
                    })
                    ->copyable()
                    ->copyMessage('Token copied'),

                Tables\Columns\TextColumn::make('created_at')
                    ->since(),
            ])
            ->actions([
                Tables\Actions\Action::make('copy')
                    ->icon('heroicon-o-clipboard-document')
                    ->action(function (ApiToken $record) {
                        Notification::make()
                            ->title('Token copied to clipboard')
                            ->body($record->token)
                            ->success()
                            ->send();
                    }),

                Tables\Actions\DeleteAction::make(),
            ]);
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListApiTokens::route('/'),
            'create' => Pages\CreateApiToken::route('/create'),
        ];
    }
}
