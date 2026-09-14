import KpiRow from './KpiRow';
import RiskArc from './RiskArc';
import AlertsChart from './AlertsChart';
import EventStream from './EventStream';
import CampaignStrip from './CampaignStrip';
import AICopilotPanel from '../panels/AICopilotPanel';

export default function OverviewPage() {
  return (
    <div className="flex-1 min-h-0 flex flex-col gap-2 p-3 overflow-y-auto scrollbar-cyber">
      <KpiRow />
      <div className="grid gap-2 grid-cols-1 xl:grid-cols-[minmax(0,2fr)_minmax(340px,1fr)]">
        <div className="flex flex-col gap-2">
          <div className="h-[232px]">
            <AlertsChart />
          </div>
          <div className="h-[460px]">
            <EventStream />
          </div>
        </div>
        <div className="flex flex-col gap-2">
          <RiskArc />
          <div className="h-[220px]">
            <CampaignStrip />
          </div>
          <div className="h-[420px]">
            <AICopilotPanel />
          </div>
        </div>
      </div>
    </div>
  );
}
