// Tiny, typed EventSource wrapper with auto-reconnect semantics.
// Browsers already retry automatically; this helper centralises the common
// patterns: typed event handlers, JSON decoding, disposal.

export type SseHandlers<T = unknown> = {
  onEvent?: (event: string, data: T) => void;
  onOpen?: () => void;
  onError?: (err: Event) => void;
};

export function subscribe<T = unknown>(
  url: string,
  events: string[],
  handlers: SseHandlers<T>,
): () => void {
  let es: EventSource | null = null;
  let closed = false;

  const listeners: Array<[string, (ev: MessageEvent) => void]> = [];

  const open = () => {
    if (closed) return;
    es = new EventSource(url);
    handlers.onOpen && es.addEventListener("open", handlers.onOpen);
    handlers.onError &&
      es.addEventListener("error", (e) => handlers.onError?.(e));

    for (const name of events) {
      const fn = (ev: MessageEvent) => {
        if (!handlers.onEvent) return;
        try {
          const parsed = ev.data ? JSON.parse(ev.data) : null;
          handlers.onEvent(name, parsed as T);
        } catch {
          /* ignore malformed */
        }
      };
      es.addEventListener(name, fn as EventListener);
      listeners.push([name, fn]);
    }
  };

  open();

  return () => {
    closed = true;
    if (es) {
      for (const [name, fn] of listeners) {
        es.removeEventListener(name, fn as EventListener);
      }
      es.close();
      es = null;
    }
  };
}
