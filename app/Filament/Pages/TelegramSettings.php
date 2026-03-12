<?php

namespace App\Filament\Pages;

use App\Models\TelegramConfig;
use Filament\Actions\Action;
use Filament\Forms\Components\Section;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Forms\Concerns\InteractsWithForms;
use Filament\Forms\Contracts\HasForms;
use Filament\Forms\Form;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Illuminate\Support\Facades\Http;

class TelegramSettings extends Page implements HasForms
{
    use InteractsWithForms;

    protected static ?string $navigationIcon = 'heroicon-o-paper-airplane';

    protected static ?string $navigationGroup = 'Settings';

    protected static ?string $navigationLabel = 'Telegram';

    protected static ?string $title = 'Telegram Settings';

    protected static ?int $navigationSort = 4;

    protected static string $view = 'filament.pages.telegram-settings';

    public ?array $data = [];

    public function mount(): void
    {
        $config = TelegramConfig::firstOrNew(
            ['organization_id' => auth()->user()->organization_id],
        );

        $this->form->fill($config->toArray());
    }

    public function form(Form $form): Form
    {
        return $form
            ->schema([
                Section::make('Bot Configuration')
                    ->schema([
                        TextInput::make('bot_token')
                            ->label('Bot Token')
                            ->password()
                            ->revealable()
                            ->maxLength(255),

                        TextInput::make('chat_id')
                            ->label('Chat ID')
                            ->maxLength(255),

                        Toggle::make('enabled')
                            ->label('Enable Telegram Notifications'),
                    ]),

                Section::make('Notification Levels')
                    ->description('Choose which severity levels trigger Telegram messages.')
                    ->schema([
                        Toggle::make('notify_critical')
                            ->label('Critical Alerts')
                            ->default(true),

                        Toggle::make('notify_high')
                            ->label('High Alerts')
                            ->default(true),

                        Toggle::make('notify_medium')
                            ->label('Medium Alerts')
                            ->default(false),

                        Toggle::make('notify_offline')
                            ->label('Server Offline')
                            ->default(true),
                    ]),
            ])
            ->statePath('data');
    }

    public function save(): void
    {
        $data = $this->form->getState();

        TelegramConfig::updateOrCreate(
            ['organization_id' => auth()->user()->organization_id],
            $data,
        );

        Notification::make()
            ->title('Telegram settings saved')
            ->success()
            ->send();
    }

    public function sendTest(): void
    {
        $data = $this->form->getState();

        if (empty($data['bot_token']) || empty($data['chat_id'])) {
            Notification::make()
                ->title('Missing bot token or chat ID')
                ->danger()
                ->send();
            return;
        }

        try {
            $response = Http::post(
                "https://api.telegram.org/bot{$data['bot_token']}/sendMessage",
                [
                    'chat_id' => $data['chat_id'],
                    'text' => "✅ StarPulse test message — your Telegram integration is working!",
                    'parse_mode' => 'HTML',
                ],
            );

            if ($response->successful() && $response->json('ok')) {
                Notification::make()
                    ->title('Test message sent successfully')
                    ->success()
                    ->send();
            } else {
                Notification::make()
                    ->title('Telegram API error')
                    ->body($response->json('description', 'Unknown error'))
                    ->danger()
                    ->send();
            }
        } catch (\Exception $e) {
            Notification::make()
                ->title('Failed to send test message')
                ->body($e->getMessage())
                ->danger()
                ->send();
        }
    }

    protected function getHeaderActions(): array
    {
        return [
            Action::make('sendTest')
                ->label('Send Test Message')
                ->icon('heroicon-o-paper-airplane')
                ->action('sendTest')
                ->color('info'),
        ];
    }
}
