<?php

namespace App\Filament\Pages;

use App\Models\DeploymentLock as DeploymentLockModel;
use Filament\Forms\Components\CheckboxList;
use Filament\Forms\Components\Section;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Forms\Concerns\InteractsWithForms;
use Filament\Forms\Contracts\HasForms;
use Filament\Forms\Form;
use Filament\Notifications\Notification;
use Filament\Pages\Page;

class DeploymentLock extends Page implements HasForms
{
    use InteractsWithForms;

    protected static ?string $navigationIcon = 'heroicon-o-lock-closed';

    protected static ?string $navigationGroup = 'Security';

    protected static ?string $navigationLabel = 'Deployment Lock';

    protected static ?string $title = 'Deployment Lock';

    protected static ?int $navigationSort = 1;

    protected static string $view = 'filament.pages.deployment-lock';

    public ?array $data = [];

    public function mount(): void
    {
        $lock = DeploymentLockModel::firstOrNew(
            ['organization_id' => auth()->user()->organization_id],
        );

        $this->form->fill($lock->toArray());
    }

    public function form(Form $form): Form
    {
        return $form
            ->schema([
                Section::make('Lock Window')
                    ->description('Block deployments during a recurring time window.')
                    ->schema([
                        Toggle::make('enabled')
                            ->label('Enable Deployment Lock'),

                        TextInput::make('lock_start')
                            ->label('Lock Start (HH:MM)')
                            ->placeholder('18:00')
                            ->maxLength(5),

                        TextInput::make('lock_end')
                            ->label('Lock End (HH:MM)')
                            ->placeholder('08:00')
                            ->maxLength(5),

                        Select::make('timezone')
                            ->options(collect([
                                'UTC',
                                'America/New_York',
                                'America/Chicago',
                                'America/Denver',
                                'America/Los_Angeles',
                                'Europe/London',
                                'Europe/Berlin',
                                'Europe/Paris',
                                'Asia/Tokyo',
                                'Asia/Shanghai',
                                'Asia/Kolkata',
                                'Australia/Sydney',
                            ])->mapWithKeys(fn ($tz) => [$tz => $tz]))
                            ->searchable(),

                        CheckboxList::make('allowed_days')
                            ->label('Active Days')
                            ->options([
                                'Mon' => 'Monday',
                                'Tue' => 'Tuesday',
                                'Wed' => 'Wednesday',
                                'Thu' => 'Thursday',
                                'Fri' => 'Friday',
                                'Sat' => 'Saturday',
                                'Sun' => 'Sunday',
                            ])
                            ->columns(4),
                    ]),

                Section::make('Webhook')
                    ->description('Point your CI/CD webhook to this URL.')
                    ->schema([
                        TextInput::make('webhook_secret')
                            ->label('Webhook Secret')
                            ->disabled()
                            ->dehydrated(false)
                            ->suffixAction(
                                \Filament\Forms\Components\Actions\Action::make('copySecret')
                                    ->icon('heroicon-o-clipboard-document')
                                    ->action(function ($state) {
                                        Notification::make()
                                            ->title('Secret copied')
                                            ->body($state)
                                            ->success()
                                            ->send();
                                    })
                            ),
                    ]),
            ])
            ->statePath('data');
    }

    public function getWebhookUrl(): string
    {
        $orgId = auth()->user()->organization_id;
        return config('app.url') . "/api/webhook/deploy/{$orgId}";
    }

    public function save(): void
    {
        $data = $this->form->getState();

        DeploymentLockModel::updateOrCreate(
            ['organization_id' => auth()->user()->organization_id],
            $data,
        );

        Notification::make()
            ->title('Deployment lock settings saved')
            ->success()
            ->send();
    }
}
