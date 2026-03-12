<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AlertGroup extends Model
{
    public const SEVERITIES = ['critical', 'high', 'medium', 'low'];

    public const CATEGORIES = [
        'auth',
        'network',
        'filesystem',
        'process',
        'package',
        'config',
        'resource',
        'malware',
    ];

    protected $fillable = [
        'organization_id',
        'agent_id',
        'fingerprint',
        'category',
        'severity',
        'title',
        'first_seen',
        'last_seen',
        'count',
        'last_detail',
        'last_data',
        'hostname',
    ];

    protected function casts(): array
    {
        return [
            'first_seen' => 'datetime',
            'last_seen' => 'datetime',
            'last_data' => 'array',
            'count' => 'integer',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class);
    }

    public function getSuggestionAttribute(): string
    {
        $title = strtolower($this->title);
        $category = strtolower($this->category);

        $suggestions = [
            'file_integrity' => [
                'mismatch' => "Unexpected file changes detected. Review the modified files and verify they were part of an authorized deployment or update. If not, investigate for tampering:\n\n1. Compare against your last known-good backup\n2. Check `git log` or deployment logs for recent changes\n3. If unauthorized, isolate the server and audit access logs\n4. Rebuild the FIM baseline after confirming the files are clean: `python3 /opt/sentinel/agent/agent.py --config /etc/sentinel/agent.conf --baseline`",
                'missing' => "Files from the baseline are missing. This could be a legitimate removal (package update, cleanup) or a sign of tampering:\n\n1. Check if a package was recently updated: `apt list --upgradable` or `rpm -qa --last`\n2. Review `/var/log/auth.log` for suspicious access\n3. Rebuild the baseline once verified: `python3 /opt/sentinel/agent/agent.py --config /etc/sentinel/agent.conf --baseline`",
                'default' => "File integrity alert detected. Review the affected files, verify against deployment history, and rebuild the baseline if changes are legitimate.",
            ],
            'crypto_mining' => [
                'default' => "Potential crypto mining activity detected. This is a critical security event:\n\n1. Check running processes: `ps aux | grep -i -E 'xmrig|minerd|cpuminer'`\n2. Check CPU usage: `top -bn1 | head -20`\n3. Inspect cron jobs: `crontab -l` and `ls /etc/cron.*`\n4. Check for suspicious network connections: `ss -tunp | grep -E '3333|4444|5555'`\n5. Kill suspicious processes, remove binaries, and audit how access was gained",
            ],
            'http_anomaly' => [
                'default' => "Unusual HTTP traffic patterns detected. This could indicate a scanning attack, brute force, or DDoS:\n\n1. Review access logs: `tail -100 /var/log/nginx/access.log`\n2. Look for repeated IPs: `awk '{print \$1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head`\n3. Consider rate-limiting with fail2ban or Cloudflare WAF rules\n4. Block offending IPs if confirmed malicious: `ufw deny from <IP>`",
            ],
            'network' => [
                'default' => "Suspicious network activity detected. Investigate open connections and listening ports:\n\n1. Check listening ports: `ss -tlnp`\n2. Check established connections: `ss -tnp`\n3. Look for connections to known-bad ports or IPs\n4. Review firewall rules: `ufw status` or `iptables -L -n`\n5. If a new service appeared, verify it's authorized",
            ],
            'resource' => [
                'ram' => "RAM usage is above the alert threshold. Investigate what's consuming memory:\n\n1. Check top memory consumers: `ps aux --sort=-%mem | head -15`\n2. Check for memory leaks: `free -h` and compare over time\n3. Review OOM killer logs: `dmesg | grep -i 'out of memory'`\n4. Consider increasing RAM or optimizing high-usage services\n5. Restart memory-leaking services if identified",
                'cpu' => "CPU load is above the alert threshold. Investigate what's driving the load:\n\n1. Check top CPU consumers: `ps aux --sort=-%cpu | head -15`\n2. Check load average trend: `uptime` and `sar -u 1 5`\n3. Look for runaway processes or cron jobs\n4. If a web server, check for traffic spikes in access logs\n5. Consider scaling or optimizing high-CPU services",
                'disk' => "Disk usage is above the alert threshold. Free up space before the disk fills completely:\n\n1. Find largest files: `du -ah / | sort -rh | head -20`\n2. Check log sizes: `du -sh /var/log/*`\n3. Clean package cache: `apt clean` or `yum clean all`\n4. Remove old kernels: `apt autoremove`\n5. Check for large temp files: `du -sh /tmp /var/tmp`\n6. Consider adding storage or setting up log rotation",
                'default' => "Server resource usage is above the alert threshold. Check `top`, `free -h`, and `df -h` to identify the pressure point and take action before it impacts service availability.",
            ],
        ];

        $categorySuggestions = $suggestions[$category] ?? $suggestions['file_integrity'] ?? [];

        foreach ($categorySuggestions as $keyword => $suggestion) {
            if ($keyword !== 'default' && str_contains($title, $keyword)) {
                return $suggestion;
            }
        }

        return $categorySuggestions['default'] ?? 'Review this alert and investigate the affected system. Check server logs and recent changes for context.';
    }
}
