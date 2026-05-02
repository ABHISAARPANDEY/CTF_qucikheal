import { useCallback, useContext, useSyncExternalStore } from 'react';
import { RealtimeStoreContext } from './RealtimeStoreContext';







































const identity = (s) => s;

export function useRealtime(selector = identity) {
  const store = useContext(RealtimeStoreContext);
  if (store === null) {
    throw new Error(
      'useRealtime must be used inside a <RealtimeProvider>. ' +
      'Wrap your app root with <RealtimeProvider>...</RealtimeProvider>.'
    );
  }



  const getSnapshot = useCallback(() => selector(store.getState()), [store, selector]);

  return useSyncExternalStore(store.subscribe, getSnapshot, getSnapshot);
}