<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\DeploymentAttempt;
use App\Models\DeploymentLock;
use App\Models\Organization;
use App\Services\TelegramService;
use Illuminate\Http\Request;

class WebhookController extends Controller
{
    public function deploy(Request $request, Organization $organization)
    {
        $lock = DeploymentLock::where('organization_id', $organization->id)->first();

        if ($lock && $lock->webhook_secret) {
            $secret = $request->header('X-Webhook-Secret')
                ?? $request->query('secret');
            if ($secret !== $lock->webhook_secret) {
                return response()->json(['error' => 'Invalid secret'], 403);
            }
        }

        $source = 'unknown';
        $action = 'deploy';
        $ref = null;

        if ($request->hasHeader('X-GitHub-Event')) {
            $source = 'github';
            $action = $request->header('X-GitHub-Event');
            $ref = data_get($request->all(), 'ref');
        } elseif ($request->hasHeader('X-Gitlab-Event')) {
            $source = 'gitlab';
            $action = $request->header('X-Gitlab-Event');
            $ref = data_get($request->all(), 'ref');
        }

        $isLocked = $lock && $lock->enabled && $lock->isLocked();
        $status = $isLocked ? 'blocked' : 'allowed';

        $attempt = DeploymentAttempt::create([
            'organization_id' => $organization->id,
            'source' => $source,
            'action' => $action,
            'status' => $status,
            'ref' => $ref,
            'payload' => $request->all(),
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);

        if ($isLocked) {
            try {
                TelegramService::notifyDeployBlocked($organization->id, [
                    'source' => $source,
                    'action' => $action,
                    'ref' => $ref,
                    'ip' => $request->ip(),
                ]);
            } catch (\Throwable $e) {
                // fail silently
            }
        }

        return response()->json([
            'status' => $status,
            'message' => $isLocked
                ? 'Deployment blocked: outside allowed window'
                : 'Deployment allowed',
            'attempt_id' => $attempt->id,
        ], $isLocked ? 423 : 200);
    }
}
