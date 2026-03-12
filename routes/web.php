<?php

use App\Http\Controllers\Api\AgentDownloadController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/agent.py', [AgentDownloadController::class, 'agentPy']);
Route::get('/install.sh', [AgentDownloadController::class, 'installSh']);
