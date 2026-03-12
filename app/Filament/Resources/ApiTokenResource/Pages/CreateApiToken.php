<?php

namespace App\Filament\Resources\ApiTokenResource\Pages;

use App\Filament\Resources\ApiTokenResource;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\CreateRecord;

class CreateApiToken extends CreateRecord
{
    protected static string $resource = ApiTokenResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        $data['organization_id'] = auth()->user()->organization_id;

        return $data;
    }

    protected function afterCreate(): void
    {
        Notification::make()
            ->title('API Token Created')
            ->body("Save this token now — it won't be shown in full again: {$this->record->token}")
            ->success()
            ->persistent()
            ->send();
    }
}
