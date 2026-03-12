<?php

use App\Http\Controllers\Api\AgentDownloadController;
use App\Http\Controllers\Api\IngestController;
use App\Http\Controllers\Api\WebhookController;
use Illuminate\Support\Facades\Route;

Route::post('/ingest', [IngestController::class, 'store']);

Route::post('/webhook/deploy/{organization}', [WebhookController::class, 'deploy']);

Route::get('/agent.py', [AgentDownloadController::class, 'agentPy']);
Route::get('/install.sh', [AgentDownloadController::class, 'installSh']);

Route::get('/status', fn () => response()->json(['status' => 'ok', 'version' => '3.0']));

// #region agent log
Route::get('/debug-check', function () {
    $agentPyPath = base_path('agent/agent.py');
    $agentSnippet = file_exists($agentPyPath)
        ? substr(file_get_contents($agentPyPath, false, null, 0, 2000), 0, 2000)
        : 'FILE NOT FOUND';

    $hasHeartbeatFix = str_contains($agentSnippet, 'Heartbeat OK');
    $hasOldBug = str_contains($agentSnippet, 'if not alerts');

    $hasColumn = \Illuminate\Support\Facades\Schema::hasColumn('agents', 'registered_address');

    $agentCount = \App\Models\Agent::count();
    $recentLogs = [];
    $logPath = storage_path('logs/laravel.log');
    if (file_exists($logPath)) {
        $lines = file($logPath);
        $recentLogs = array_slice($lines, -10);
    }

    return response()->json([
        'deploy_check' => [
            'heartbeat_fix_present' => $hasHeartbeatFix,
            'old_bug_present' => $hasOldBug,
        ],
        'db_check' => [
            'registered_address_column' => $hasColumn,
            'agent_count' => $agentCount,
        ],
        'recent_logs' => array_map('trim', $recentLogs),
    ]);
});
// #endregion
