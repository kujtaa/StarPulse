<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\AlertGroup;
use App\Models\Agent;
use App\Models\ApiToken;
use App\Services\TelegramService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class IngestController extends Controller
{
    public function store(Request $request)
    {
        $tokenValue = $request->header('X-Sentinel-Token');
        if (! $tokenValue) {
            return response()->json(['error' => 'Missing token'], 401);
        }

        $apiToken = ApiToken::where('token', $tokenValue)->first();
        if (! $apiToken) {
            return response()->json(['error' => 'Invalid token'], 403);
        }

        $orgId = $apiToken->organization_id;

        $data = $request->validate([
            'agent_id' => 'required|string',
            'hostname' => 'nullable|string',
            'os_info' => 'nullable|string',
            'agent_ver' => 'nullable|string',
            'tags' => 'nullable|string',
            'meta' => 'nullable|array',
            'alerts' => 'nullable|array',
            'alerts.*.category' => 'required|string',
            'alerts.*.severity' => 'required|string',
            'alerts.*.title' => 'required|string',
            'alerts.*.detail' => 'nullable|string',
            'alerts.*.data' => 'nullable|array',
            'alerts.*.hostname' => 'nullable|string',
        ]);

        $connectingIp = $request->ip();
        $agentHostname = $data['hostname'] ?? null;

        $pendingMatch = Agent::where('organization_id', $orgId)
            ->whereNull('last_seen')
            ->whereNotNull('registered_address')
            ->where(function ($q) use ($connectingIp, $agentHostname) {
                $q->where('registered_address', $connectingIp)
                  ->when($agentHostname, fn ($q2) => $q2->orWhere('registered_address', $agentHostname)
                      ->orWhere('hostname', $agentHostname));
            })
            ->first();

        $registeredAddress = $pendingMatch?->registered_address;
        $pendingMatch?->delete();

        $agent = Agent::updateOrCreate(
            ['id' => $data['agent_id'], 'organization_id' => $orgId],
            [
                'hostname' => $data['hostname'] ?? null,
                'ip' => $connectingIp,
                'registered_address' => $registeredAddress ?? null,
                'os_info' => $data['os_info'] ?? null,
                'agent_ver' => $data['agent_ver'] ?? null,
                'last_seen' => now(),
                'first_seen' => now(),
                'meta' => $data['meta'] ?? null,
                'tags' => $data['tags'] ?? null,
                'offline_alerted' => false,
            ]
        );

        if (! $agent->wasRecentlyCreated) {
            $agent->update(['last_seen' => now(), 'offline_alerted' => false]);
        }

        $newCount = 0;
        $alerts = $data['alerts'] ?? [];

        foreach ($alerts as $alert) {
            $category = $alert['category'];
            $title = $alert['title'];
            $severity = $alert['severity'];
            $detail = $alert['detail'] ?? '';
            $alertData = $alert['data'] ?? null;
            $alertHostname = $alert['hostname'] ?? $data['hostname'];

            $fingerprint = substr(hash('sha256', $data['agent_id'].':'.$category.':'.$title), 0, 16);

            $existing = AlertGroup::where('agent_id', $data['agent_id'])
                ->where('fingerprint', $fingerprint)
                ->where('last_seen', '>=', now()->subSeconds(300))
                ->orderByDesc('last_seen')
                ->first();

            if ($existing) {
                $existing->update([
                    'count' => $existing->count + 1,
                    'last_seen' => now(),
                    'last_detail' => $detail,
                    'last_data' => $alertData,
                    'severity' => $severity,
                ]);
            } else {
                AlertGroup::create([
                    'organization_id' => $orgId,
                    'agent_id' => $data['agent_id'],
                    'fingerprint' => $fingerprint,
                    'category' => $category,
                    'severity' => $severity,
                    'title' => $title,
                    'first_seen' => now(),
                    'last_seen' => now(),
                    'count' => 1,
                    'last_detail' => $detail,
                    'last_data' => $alertData,
                    'hostname' => $alertHostname,
                ]);
                $newCount++;

                try {
                    TelegramService::notifyAlert($orgId, [
                        'severity' => $severity,
                        'category' => $category,
                        'title' => $title,
                        'detail' => $detail,
                        'hostname' => $alertHostname,
                    ]);
                } catch (\Throwable $e) {
                    Log::warning('Telegram notification failed: '.$e->getMessage());
                }
            }
        }

        $latestVersion = null;
        $agentPath = base_path('agent/agent.py');
        if (file_exists($agentPath) && preg_match('/^AGENT_VERSION\s*=\s*["\'](.+?)["\']/m', file_get_contents($agentPath), $m)) {
            $latestVersion = $m[1];
        }

        return response()->json([
            'ok' => true,
            'new_alerts' => $newCount,
            'total' => count($alerts),
            'latest_agent_version' => $latestVersion,
        ]);
    }
}
