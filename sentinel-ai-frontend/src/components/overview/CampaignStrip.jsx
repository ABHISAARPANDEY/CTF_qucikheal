import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Radar } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Empty } from '../ui/empty';
import { detectionCampaigns } from '../../lib/api';
import { fmtPct } from '../../lib/format';

export default function CampaignStrip() {
  const [campaigns, setCampaigns] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    let alive = true;
    const tick = () =>
      detectionCampaigns()
        .then((r) => alive && setCampaigns(r.campaigns ?? []))
        .catch(() => void 0);
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  return (
    <Card className="h-full min-h-0 flex flex-col">
      <CardHeader>
        <CardTitle>Distributed campaigns</CardTitle>
        <span className="text-[11px] text-fg-3">fingerprint · UA + endpoint</span>
      </CardHeader>
      <CardContent className="p-2 flex-1 min-h-0 overflow-y-auto scrollbar-cyber">
        {campaigns.length === 0 ? (
          <Empty icon={Radar} title="No active campaigns" hint="A campaign is one client fingerprint failing from many IPs across many subnets." className="py-6" />
        ) : (
          <ul className="space-y-1.5">
            {campaigns.map((c) => (
              <li key={c.campaign_id}>
                <button
                  type="button"
                  onClick={() => navigate(`/entities/campaign/${c.campaign_id}`)}
                  className="w-full text-left rounded-md border border-sev-high/30 bg-sev-high/5 px-3 py-2 hover:bg-sev-high/10 transition-cyber focus-ring"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[11.5px] text-fg-0 truncate">{c.user_agent}</span>
                    <span className="font-mono text-[11px] text-fg-2 shrink-0">{c.endpoint}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-3 text-[11px] text-fg-2 font-mono tabular">
                    <span><b className="text-fg-0">{c.distinct_ips}</b> IPs</span>
                    <span><b className="text-fg-0">{c.distinct_subnets}</b> /24s</span>
                    <span><b className="text-fg-0">{c.distinct_users}</b> users</span>
                    <span>fail {fmtPct(c.fail_ratio)}</span>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
