<x-filament-panels::page>
    <form wire:submit="save" class="space-y-6">
        {{ $this->form }}

        <x-filament::section>
            <x-slot name="heading">Webhook URL</x-slot>
            <x-slot name="description">Configure your GitHub/GitLab webhook to point to this URL.</x-slot>

            <div class="relative">
                <pre class="rounded-lg bg-gray-900 p-4 text-sm text-cyan-400 font-mono overflow-x-auto border border-gray-700"><code>{{ $this->getWebhookUrl() }}</code></pre>
                <button
                    type="button"
                    x-data="{ copied: false }"
                    x-on:click="
                        navigator.clipboard.writeText(@js($this->getWebhookUrl()));
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
        </x-filament::section>

        <x-filament::button type="submit">
            Save Settings
        </x-filament::button>
    </form>
</x-filament-panels::page>
