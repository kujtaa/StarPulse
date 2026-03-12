<x-filament-panels::page>
    <div class="space-y-6">
        <x-filament::section>
            <x-slot name="heading">Add a Server</x-slot>
            <x-slot name="description">Run this command on any Linux server to connect it to your dashboard. It will appear on the Servers page within 60 seconds.</x-slot>

            <div class="space-y-4">
                {{-- Token selector --}}
                <div>
                    <label for="token-select" class="block text-sm font-medium text-gray-300 mb-1">API Token</label>
                    <select
                        id="token-select"
                        wire:model.live="selectedToken"
                        class="w-full rounded-lg border-gray-600 bg-gray-800 text-white shadow-sm focus:border-cyan-500 focus:ring-cyan-500"
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
                    <strong class="text-white">Copy the install command</strong> above and paste it into your server's terminal (requires root/sudo).
                </li>
                <li>
                    <strong class="text-white">The agent will install</strong> as a systemd service and begin sending heartbeats and security events immediately.
                </li>
                <li>
                    <strong class="text-white">Verify the connection</strong> — your server should appear on the <a href="{{ route('filament.admin.resources.agents.index') }}" class="text-cyan-400 hover:underline">Servers</a> page within 60 seconds.
                </li>
                <li>
                    <strong class="text-white">Configure alerts</strong> via the <a href="{{ route('filament.admin.pages.telegram-settings') }}" class="text-cyan-400 hover:underline">Telegram Settings</a> page to receive real-time notifications.
                </li>
            </ol>
        </x-filament::section>
    </div>
</x-filament-panels::page>
