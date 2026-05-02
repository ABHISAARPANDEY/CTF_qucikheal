














const target = new EventTarget();

export const bus = {
  emit(name, detail) {
    target.dispatchEvent(new CustomEvent(name, { detail }));
  },
  on(name, handler) {
    const wrapped = (e) => handler(e.detail);
    target.addEventListener(name, wrapped);
    return () => target.removeEventListener(name, wrapped);
  }
};

export const EVENTS = {

  SIMULATE_REQUEST: 'sentinel:simulate-request'
};