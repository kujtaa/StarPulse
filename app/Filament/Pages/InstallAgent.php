<?php

namespace App\Filament\Pages;

use App\Models\Agent;
use App\Models\ApiToken;
use Filament\Pages\Page;
use Illuminate\Support\Str;

class InstallAgent extends Page
{
    protected static ?string $title = 'Add Server';

    protected static bool $shouldRegisterNavigation = false;

    protected static string $view = 'filament.pages.install-agent';

    public int $step = 1;

    public string $registeredAddress = '';

    public string $serverLabel = '';

    public ?string $selectedToken = '';

    public ?string $createdAgentId = null;

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

    public function registerServer(): void
    {
        $this->validate([
            'registeredAddress' => ['required', 'string', 'max:255'],
            'serverLabel' => ['nullable', 'string', 'max:255'],
        ]);

        $agent = Agent::create([
            'id' => Str::uuid()->toString(),
            'organization_id' => auth()->user()->organization_id,
            'registered_address' => $this->registeredAddress,
            'hostname' => $this->serverLabel ?: null,
        ]);

        $this->createdAgentId = $agent->id;
        $this->step = 2;
    }

    public function getInstallCommand(): string
    {
        $host = config('app.url');

        return "curl -sSL {$host}/install.sh | SENTINEL_SERVER={$host} SENTINEL_TOKEN={$this->selectedToken} bash";
    }

    public function finishSetup(): void
    {
        $this->redirect(route('filament.admin.resources.agents.index'));
    }

    public function startOver(): void
    {
        $this->step = 1;
        $this->registeredAddress = '';
        $this->serverLabel = '';
        $this->createdAgentId = null;
    }
}
