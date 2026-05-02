import { useEffect, useState } from 'react';
import { RealtimeStoreContext } from './RealtimeStoreContext';
import { useRealtimeEvents } from './useRealtimeEvents';









































const INITIAL_STATE = Object.freeze({
  events: [],
  threat: null,
  riskScore: null,
  actions: [],
  explanation: null,
  telemetryLogs: [],
  scenarioEvents: [],
  systemUpdates: {},
  honeypotActivities: [],
  honeypotAnalyses: [],
  status: 'reconnecting'
});











function createRealtimeStore() {
  let state = INITIAL_STATE;
  const listeners = new Set();

  function getState() {
    return state;
  }

  function setState(patch) {

    let changed = false;
    const next = { ...state };
    for (const key of Object.keys(patch)) {
      if (!Object.is(state[key], patch[key])) {
        next[key] = patch[key];
        changed = true;
      }
    }
    if (!changed) return;
    state = next;
    listeners.forEach((l) => l());
  }

  function subscribe(listener) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }

  return { getState, setState, subscribe };
}

export function RealtimeProvider({ children, ...wsOptions }) {

  const [store] = useState(() => createRealtimeStore());


  const { data, status } = useRealtimeEvents(wsOptions);



  useEffect(() => {
    store.setState({
      events: data.events,
      threat: data.currentThreat,
      riskScore: data.riskScore,
      actions: data.actions,
      explanation: data.explanation,
      telemetryLogs: data.telemetryLogs ?? [],
      scenarioEvents: data.scenarioEvents ?? [],
      systemUpdates: data.systemUpdates ?? {},
      honeypotActivities: data.honeypotActivities ?? [],
      honeypotAnalyses: data.honeypotAnalyses ?? [],
      status
    });
  }, [data, status, store]);

  return (
    <RealtimeStoreContext.Provider value={store}>
      {children}
    </RealtimeStoreContext.Provider>);

}