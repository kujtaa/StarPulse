<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;

class AgentDownloadController extends Controller
{
    public function agentPy()
    {
        $path = base_path('agent/agent.py');
        if (! file_exists($path)) {
            abort(404, 'Agent not found');
        }

        return response()->file($path, ['Content-Type' => 'text/plain']);
    }

    public function installSh()
    {
        $path = base_path('agent/install.sh');
        if (! file_exists($path)) {
            abort(404, 'Install script not found');
        }

        return response()->file($path, ['Content-Type' => 'text/plain']);
    }
}
