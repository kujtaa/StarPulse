<?php

namespace App\Services;

use App\Models\TelegramConfig;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class TelegramService
{
    public static function notifyAlert(int $orgId, array $alert): void
    {
        $config = TelegramConfig::where('organization_id', $orgId)->first();
        if (! $config || ! $config->enabled || ! $config->bot_token || ! $config->chat_id) {
            return;
        }

        $severity = $alert['severity'] ?? 'low';

        if ($severity === 'critical' && ! $config->notify_critical) return;
        if ($severity === 'high' && ! $config->notify_high) return;
        if ($severity === 'medium' && ! $config->notify_medium) return;
        if ($severity === 'low') return;

        $emoji = match ($severity) {
            'critical' => '🔴',
            'high' => '🟠',
            'medium' => '🟡',
            default => 'ℹ️',
        };

        $message = "{$emoji} *{$severity} alert*\n\n"
            ."*{$alert['title']}*\n"
            ."Host: `{$alert['hostname']}`\n"
            ."Category: {$alert['category']}\n";

        if (! empty($alert['detail'])) {
            $message .= "Detail: {$alert['detail']}\n";
        }

        static::sendMessage($config, $message);
    }

    public static function notifyOffline(int $orgId, string $hostname, string $agentId): void
    {
        $config = TelegramConfig::where('organization_id', $orgId)->first();
        if (! $config || ! $config->enabled || ! $config->notify_offline || ! $config->bot_token || ! $config->chat_id) {
            return;
        }

        $message = "⚫ *Server offline*\n\n"
            ."Host: `{$hostname}`\n"
            ."Agent: `{$agentId}`\n"
            .'The agent has not checked in recently.';

        static::sendMessage($config, $message);
    }

    public static function notifyDeployBlocked(int $orgId, array $data): void
    {
        $config = TelegramConfig::where('organization_id', $orgId)->first();
        if (! $config || ! $config->enabled || ! $config->bot_token || ! $config->chat_id) {
            return;
        }

        $message = "🚫 *Deployment blocked*\n\n"
            ."Source: {$data['source']}\n"
            ."Action: {$data['action']}\n";

        if (! empty($data['ref'])) {
            $message .= "Ref: `{$data['ref']}`\n";
        }
        if (! empty($data['ip'])) {
            $message .= "IP: `{$data['ip']}`\n";
        }

        $message .= "\nDeployment was blocked because it occurred outside the allowed window.";

        static::sendMessage($config, $message);
    }

    public static function sendTestMessage(int $orgId): bool
    {
        $config = TelegramConfig::where('organization_id', $orgId)->first();
        if (! $config || ! $config->bot_token || ! $config->chat_id) {
            return false;
        }

        return static::sendMessage($config, "✅ *StarPulse test*\n\nTelegram notifications are working!");
    }

    protected static function sendMessage(TelegramConfig $config, string $text): bool
    {
        $url = "https://api.telegram.org/bot{$config->bot_token}/sendMessage";

        try {
            $response = Http::timeout(10)->post($url, [
                'chat_id' => $config->chat_id,
                'text' => $text,
                'parse_mode' => 'Markdown',
                'disable_web_page_preview' => true,
            ]);

            if (! $response->successful()) {
                Log::warning('Telegram API error', ['status' => $response->status(), 'body' => $response->body()]);

                return false;
            }

            return true;
        } catch (\Throwable $e) {
            Log::warning('Telegram send failed: '.$e->getMessage());

            return false;
        }
    }
}
