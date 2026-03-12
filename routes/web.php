<?php

use App\Http\Controllers\Api\AgentDownloadController;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => redirect('/app'));

Route::get('/agent.py', [AgentDownloadController::class, 'agentPy']);
Route::get('/install.sh', [AgentDownloadController::class, 'installSh']);
