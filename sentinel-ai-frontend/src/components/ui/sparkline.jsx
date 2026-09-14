import { Line, LineChart, ResponsiveContainer, YAxis } from 'recharts';

export function Sparkline({ data, dataKey = 'v', width = 96, height = 26, color = 'var(--color-fg-2)' }) {
  if (!data?.length) return <div style={{ width, height }} />;
  return (
    <div style={{ width, height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
          <YAxis hide domain={['dataMin', 'dataMax']} />
          <Line type="monotone" dataKey={dataKey} stroke={color} strokeWidth={1.5} dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
