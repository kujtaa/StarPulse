<?php

namespace App\Filament\Pages\Auth;

use App\Models\ApiToken;
use App\Models\Organization;
use Filament\Forms\Components\TextInput;
use Filament\Pages\Auth\Register as BaseRegister;
use Illuminate\Support\Str;

class Register extends BaseRegister
{
    protected function getForms(): array
    {
        return [
            'form' => $this->form(
                $this->makeForm()
                    ->schema([
                        TextInput::make('organization_name')
                            ->label('Organization Name')
                            ->required()
                            ->maxLength(255),
                        $this->getNameFormComponent(),
                        $this->getEmailFormComponent(),
                        $this->getPasswordFormComponent(),
                        $this->getPasswordConfirmationFormComponent(),
                    ])
                    ->statePath('data'),
            ),
        ];
    }

    protected function handleRegistration(array $data): \App\Models\User
    {
        $org = Organization::create([
            'name' => $data['organization_name'],
            'slug' => Str::slug($data['organization_name']),
        ]);

        $user = \App\Models\User::create([
            'organization_id' => $org->id,
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => $data['password'],
        ]);

        ApiToken::create([
            'organization_id' => $org->id,
            'label' => 'default',
        ]);

        return $user;
    }
}
