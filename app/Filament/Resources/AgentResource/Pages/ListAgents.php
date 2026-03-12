<?php

namespace App\Filament\Resources\AgentResource\Pages;

use App\Filament\Resources\AgentResource;
use Filament\Actions;
use Filament\Resources\Pages\ListRecords;

class ListAgents extends ListRecords
{
    protected static string $resource = AgentResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\Action::make('addServer')
                ->label('Add Server')
                ->icon('heroicon-o-plus')
                ->color('primary')
                ->url(route('filament.admin.pages.install-agent')),
        ];
    }
}
