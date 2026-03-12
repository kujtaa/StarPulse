<x-filament-panels::page>
    <div class="space-y-6">

        {{-- Step indicator --}}
        <div class="flex items-center gap-3 text-sm">
            <span @class([
                'inline-flex items-center justify-center w-7 h-7 rounded-full text-xs font-bold',
                'bg-cyan-500 text-white' => $step === 1,
                'bg-gray-700 text-gray-400' => $step !== 1,
            ])>1</span>
            <span @class(['font-medium', 'text-white' => $step === 1, 'text-gray-500' => $step !== 1])>
                Server Details
            </span>
            <x-heroicon-o-chevron-right class="w-4 h-4 text-gray-600" />
            <span @class([
                'inline-flex items-center justify-center w-7 h-7 rounded-full text-xs font-bold',
                'bg-cyan-500 text-white' => $step === 2,
                'bg-gray-700 text-gray-400' => $step !== 2,
            ])>2</span>
            <span @class(['font-medium', 'text-white' => $step === 2, 'text-gray-500' => $step !== 2])>
                Install Agent
            </span>
        </div>

        @if ($step === 1)
            {{-- Step 1: Enter server IP/URL --}}
            <x-filament::section>
                <x-slot name="heading">Server Details</x-slot>
                <x-slot name="description">Enter the IP address or URL of the server you want to monitor.</x-slot>

                <form wire:submit="registerServer" class="space-y-4">
                    <div>
                        <label for="registeredAddress" class="fi-fo-field-wrp-label block text-sm font-medium mb-1">
                            IP Address or URL <span class="text-danger-500">*</span>
                        </label>
                        <input
                            id="registeredAddress"
                            type="text"
                            wire:model="registeredAddress"
                            placeholder="e.g. 192.168.1.100 or server.example.com"
                            class="fi-input block w-full rounded-lg border-none bg-white/5 py-1.5 px-3 text-sm text-gray-950 shadow-sm ring-1 ring-gray-950/10 focus:ring-2 focus:ring-primary-600 dark:bg-white/5 dark:text-white dark:ring-white/20"
                        />
                        @error('registeredAddress')
                            <p class="mt-1 text-sm text-danger-500">{{ $message }}</p>
                        @enderror
                    </div>

                    <div>
                        <label for="serverLabel" class="fi-fo-field-wrp-label block text-sm font-medium mb-1">
                            Label <span class="text-gray-500">(optional)</span>
                        </label>
                        <input
                            id="serverLabel"
                            type="text"
                            wire:model="serverLabel"
                            placeholder="e.g. Production Web Server"
                            class="fi-input block w-full rounded-lg border-none bg-white/5 py-1.5 px-3 text-sm text-gray-950 shadow-sm ring-1 ring-gray-950/10 focus:ring-2 focus:ring-primary-600 dark:bg-white/5 dark:text-white dark:ring-white/20"
                        />
                        @error('serverLabel')
                            <p class="mt-1 text-sm text-danger-500">{{ $message }}</p>
                        @enderror
                    </div>

                    <div class="pt-2">
                        <x-filament::button type="submit" icon="heroicon-o-plus-circle">
                            Register Server
                        </x-filament::button>
                    </div>
                </form>
            </x-filament::section>
        @else
            {{-- Step 2: Install command --}}
            <x-filament::section icon="heroicon-o-check-circle" icon-color="success">
                <x-slot name="heading">Server Registered</x-slot>
                <x-slot name="description">
                    <strong class="text-white">{{ $registeredAddress }}</strong>
                    @if ($serverLabel)
                        ({{ $serverLabel }})
                    @endif
                    is now visible on the Servers page as <span class="text-amber-400 font-semibold">Pending</span>.
                    Install the agent below to activate monitoring.
                </x-slot>
            </x-filament::section>

            <x-filament::section>
                <x-slot name="heading">Install the Agent</x-slot>
                <x-slot name="description">Run this command on the server to connect it to your dashboard.</x-slot>

                <div class="space-y-4">
                    {{-- Token selector --}}
                    <div>
                        <label for="token-select" class="block text-sm font-medium text-gray-300 mb-1">API Token</label>
                        <select
                            id="token-select"
                            wire:model.live="selectedToken"
                            class="fi-input block w-full rounded-lg border-none bg-white/5 py-1.5 px-3 text-sm text-gray-950 shadow-sm ring-1 ring-gray-950/10 focus:ring-2 focus:ring-primary-600 dark:bg-white/5 dark:text-white dark:ring-white/20"
                        >
                            @foreach ($this->getTokenOptions() as $label => $token)
                                <option value="{{ $token }}">{{ $label }} — {{ Str::limit($token, 16) }}</option>
                            @endforeach
                        </select>
                    </div>

                    {{-- Install command --}}
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-1">Install Command</label>
                        <div class="relative">
                            <pre class="rounded-lg bg-gray-900 p-4 text-sm text-cyan-400 font-mono overflow-x-auto border border-gray-700"><code>{{ $this->getInstallCommand() }}</code></pre>
                            <button
                                type="button"
                                x-data="{ copied: false }"
                                x-on:click="
                                    navigator.clipboard.writeText(@js($this->getInstallCommand()));
                                    copied = true;
                                    setTimeout(() => copied = false, 2000);
                                "
                                class="absolute top-2 right-2 rounded-md bg-gray-700 p-2 text-gray-300 hover:bg-gray-600 hover:text-white transition"
                            >
                                <span x-show="!copied">
                                    <x-heroicon-o-clipboard-document class="w-4 h-4" />
                                </span>
                                <span x-show="copied" x-cloak>
                                    <x-heroicon-o-check class="w-4 h-4 text-emerald-400" />
                                </span>
                            </button>
                        </div>
                    </div>
                </div>
            </x-filament::section>

            <x-filament::section>
                <x-slot name="heading">Setup Instructions</x-slot>

                <ol class="list-decimal list-inside space-y-3 text-sm text-gray-300">
                    <li>
                        <strong class="text-white">SSH into your server</strong> at <code class="text-cyan-400">{{ $registeredAddress }}</code> and paste the install command above (requires root/sudo).
                    </li>
                    <li>
                        <strong class="text-white">The agent will install</strong> as a systemd service and begin sending heartbeats and security events immediately.
                    </li>
                    <li>
                        <strong class="text-white">Verify the connection</strong> — your server should change from <span class="text-amber-400">Pending</span> to <span class="text-emerald-400">Online</span> on the <a href="{{ route('filament.admin.resources.agents.index') }}" class="text-cyan-400 hover:underline">Servers</a> page within 60 seconds.
                    </li>
                    <li>
                        <strong class="text-white">Configure alerts</strong> via the <a href="{{ route('filament.admin.pages.telegram-settings') }}" class="text-cyan-400 hover:underline">Telegram Settings</a> page to receive real-time notifications.
                    </li>
                </ol>
            </x-filament::section>

            <div class="flex items-center gap-3">
                <x-filament::button wire:click="finishSetup" icon="heroicon-o-check-circle">
                    I've Installed the Agent
                </x-filament::button>
                <x-filament::button color="gray" wire:click="startOver" icon="heroicon-o-plus">
                    Add Another Server
                </x-filament::button>
            </div>
        @endif
    </div>
</x-filament-panels::page>
