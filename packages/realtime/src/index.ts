export type NoteChangeEvent = {
  audiencePrincipalIds: string[];
  kind: 'created' | 'deleted' | 'updated';
  noteId: string;
  occurredAt: string;
  ownerUserId: string;
};

export type NoteEventSubscription = {
  close: () => void;
};

export type SubscribeToNoteEventsOptions = {
  accessToken: string;
  baseUrl: string;
  onError?: (error: Error) => void;
  onEvent: (event: NoteChangeEvent) => void;
  path?: string;
  reconnectDelayMs?: number;
  WebSocketCtor?: WebSocketLikeConstructor;
};

type WebSocketLike = {
  close: (code?: number, reason?: string) => void;
  onclose: ((event: unknown) => void) | null;
  onerror: ((event: unknown) => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onopen: ((event: unknown) => void) | null;
};

type WebSocketLikeConstructor = new (url: string) => WebSocketLike;

const DEFAULT_NOTES_EVENTS_PATH = '/api/notes/events';
const DEFAULT_RECONNECT_DELAY_MS = 1_500;

export function buildNoteEventsUrl(baseUrl: string, accessToken: string, path = DEFAULT_NOTES_EVENTS_PATH) {
  const normalizedBaseUrl = normalizeBaseUrl(baseUrl);
  const normalizedAccessToken = accessToken.trim();

  if (!normalizedAccessToken) {
    throw new Error('Provide an access token before connecting to note realtime updates.');
  }

  const url = new URL(path, ensureTrailingSlash(normalizedBaseUrl));

  switch (url.protocol) {
    case 'http:':
      url.protocol = 'ws:';
      break;
    case 'https:':
      url.protocol = 'wss:';
      break;
    case 'ws:':
    case 'wss:':
      break;
    default:
      throw new Error('The backend URL must use http, https, ws, or wss.');
  }

  url.searchParams.set('accessToken', normalizedAccessToken);
  return url.toString();
}

export function subscribeToNoteEvents(
  options: SubscribeToNoteEventsOptions,
): NoteEventSubscription {
  const WebSocketCtor = options.WebSocketCtor ?? resolveDefaultWebSocket();

  if (!WebSocketCtor) {
    throw new Error('WebSocket is not available in this runtime.');
  }

  const reconnectDelayMs = options.reconnectDelayMs ?? DEFAULT_RECONNECT_DELAY_MS;
  const websocketUrl = buildNoteEventsUrl(
    options.baseUrl,
    options.accessToken,
    options.path ?? DEFAULT_NOTES_EVENTS_PATH,
  );

  let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  let socket: WebSocketLike | null = null;
  let closedByCaller = false;

  const scheduleReconnect = () => {
    if (closedByCaller || reconnectTimeout) {
      return;
    }

    reconnectTimeout = setTimeout(() => {
      reconnectTimeout = null;
      connect();
    }, reconnectDelayMs);
  };

  const reportError = (message: string, cause?: unknown) => {
    const error = cause instanceof Error ? cause : new Error(message);
    options.onError?.(error);
  };

  const connect = () => {
    try {
      socket = new WebSocketCtor(websocketUrl);
    } catch (error) {
      reportError('Unable to open the note realtime websocket.', error);
      scheduleReconnect();
      return;
    }

    socket.onmessage = (event) => {
      try {
        const noteEvent = parseNoteChangeEvent(event.data);

        if (!noteEvent) {
          return;
        }

        options.onEvent(noteEvent);
      } catch (error) {
        reportError('Received an invalid note realtime event.', error);
      }
    };

    socket.onerror = () => {
      reportError('The note realtime websocket reported an error.');
    };

    socket.onclose = () => {
      socket = null;

      if (!closedByCaller) {
        scheduleReconnect();
      }
    };
  };

  connect();

  return {
    close: () => {
      closedByCaller = true;

      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
      }

      socket?.close();
      socket = null;
    },
  };
}

function normalizeBaseUrl(baseUrl: string) {
  const normalizedBaseUrl = baseUrl.trim();

  if (!normalizedBaseUrl) {
    throw new Error('Set the backend URL before connecting to note realtime updates.');
  }

  return normalizedBaseUrl;
}

function ensureTrailingSlash(value: string) {
  return value.endsWith('/') ? value : `${value}/`;
}

function resolveDefaultWebSocket() {
  return globalThis.WebSocket as WebSocketLikeConstructor | undefined;
}

function parseNoteChangeEvent(data: unknown) {
  if (typeof data !== 'string') {
    return null;
  }

  const parsed = JSON.parse(data) as unknown;

  if (!isNoteChangeEvent(parsed)) {
    throw new Error('Invalid note realtime payload.');
  }

  return parsed;
}

function isNoteChangeEvent(value: unknown): value is NoteChangeEvent {
  return !!value &&
    typeof value === 'object' &&
    'audiencePrincipalIds' in value &&
    'kind' in value &&
    'noteId' in value &&
    'occurredAt' in value &&
    'ownerUserId' in value &&
    Array.isArray(value.audiencePrincipalIds) &&
    value.audiencePrincipalIds.every((principalId) => typeof principalId === 'string') &&
    (value.kind === 'created' || value.kind === 'deleted' || value.kind === 'updated') &&
    typeof value.noteId === 'string' &&
    typeof value.occurredAt === 'string' &&
    typeof value.ownerUserId === 'string';
}