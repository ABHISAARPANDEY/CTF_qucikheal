import KpiRow from './KpiRow';
import RiskArc from './RiskArc';
import AlertsChart from './AlertsChart';
import EventStream from './EventStream';
import CampaignStrip from './CampaignStrip';
import AICopilotPanel from '../panels/AICopilotPanel';

export default function OverviewPage() {
  return (
    <div className="flex-1 min-h-0 flex flex-col gap-2 p-3 overflow-y-auto xl:overflow-hidden scrollbar-cyber">
      <KpiRow />
      <div className="flex-1 min-h-0 grid gap-2 grid-cols-1 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]">
        <div className="min-h-0 flex flex-col gap-2">
          <div className="shrink-0 h-[232px]">
            <AlertsChart />
          </div>
          <div className="flex-1 min-h-[360px]">
            <EventStream />
          </div>
        </div>
        <div className="min-h-0 grid gap-2 grid-rows-[auto_minmax(160px,1fr)_minmax(220px,1.2fr)]">
          <RiskArc />
          <CampaignStrip />
          <AICopilotPanel />
        </div>
      </div>
    </div>
  );
}
