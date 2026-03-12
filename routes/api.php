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
