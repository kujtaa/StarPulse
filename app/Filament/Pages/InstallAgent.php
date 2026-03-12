<?php

namespace App\Filament\Pages;

use App\Models\ApiToken;
use Filament\Pages\Page;

class InstallAgent extends Page
{
    protected static ?string $navigationIcon = 'heroicon-o-plus-circle';

    protected static ?string $navigationGroup = 'Monitoring';

    protected static ?string $navigationLabel = 'Add Server';

    protected static ?string $title = 'Add Server';

    protected static ?int $navigationSort = 2;

    protected static string $view = 'filament.pages.install-agent';

    public ?string $selectedToken = '';

    public function mount(): void
    {
        $first = ApiToken::where('organization_id', auth()->user()->organization_id)->first();
        $this->selectedToken = $first?->token ?? '';
    }

    public function getTokenOptions(): array
    {
        return ApiToken::where('organization_id', auth()->user()->organization_id)
            ->pluck('token', 'label')
            ->toArray();
    }

    public function getInstallCommand(): string
    {
        $host = config('app.url');

        return "curl -sSL {$host}/install.sh | SENTINEL_SERVER={$host} SENTINEL_TOKEN={$this->selectedToken} bash";
    }
}
