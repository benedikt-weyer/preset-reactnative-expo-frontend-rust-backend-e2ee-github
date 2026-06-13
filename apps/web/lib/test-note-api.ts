import type { KekAsymmetricDekEncryptedPayload } from '@repo/e2ee-auth/web';

type AuthenticatedRequest = {
  baseUrl: string;
  token: string;
};

type NoteByIdRequest = AuthenticatedRequest & {
  noteId: string;
};

type SaveNoteRequest = AuthenticatedRequest & {
  payload: SaveNotePayload;
};

type UpdateNoteRequest = SaveNoteRequest & {
  noteId: string;
};

export type NoteResponse = KekAsymmetricDekEncryptedPayload & {
  createdAt: string;
  id: string;
  updatedAt: string;
};

export type SaveNotePayload = {
  encryptedDeks: Array<KekAsymmetricDekEncryptedPayload['encryptedDek'] & { userId: string }>;
  encryptedPayload: KekAsymmetricDekEncryptedPayload['encryptedPayload'];
};

export async function fetchNotes(request: AuthenticatedRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/notes'), {
    headers: {
      Authorization: `Bearer ${request.token}`,
    },
    method: 'GET',
  });

  const responseBody = (await response.json().catch(() => null)) as
    | NoteResponse[]
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  if (!Array.isArray(responseBody)) {
    throw new Error('The backend returned an invalid notes payload.');
  }

  return responseBody.map(validatePayload);
}

export async function fetchNote(request: NoteByIdRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, buildNotePath(request.noteId)), {
    headers: {
      Authorization: `Bearer ${request.token}`,
    },
    method: 'GET',
  });

  const responseBody = (await response.json().catch(() => null)) as
    | NoteResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  return validatePayload(responseBody);
}

export async function createNote(request: SaveNoteRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/notes'), {
    body: JSON.stringify(request.payload),
    headers: {
      Authorization: `Bearer ${request.token}`,
      'Content-Type': 'application/json',
    },
    method: 'POST',
  });

  const responseBody = (await response.json().catch(() => null)) as
    | NoteResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  return validatePayload(responseBody);
}

export async function updateNote(request: UpdateNoteRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, buildNotePath(request.noteId)), {
    body: JSON.stringify(request.payload),
    headers: {
      Authorization: `Bearer ${request.token}`,
      'Content-Type': 'application/json',
    },
    method: 'PUT',
  });

  const responseBody = (await response.json().catch(() => null)) as
    | NoteResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  return validatePayload(responseBody);
}

export async function deleteNote(request: NoteByIdRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, buildNotePath(request.noteId)), {
    headers: {
      Authorization: `Bearer ${request.token}`,
    },
    method: 'DELETE',
  });

  const responseBody = (await response.json().catch(() => null)) as
    | boolean
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }
}

function validatePayload(
  responseBody: NoteResponse | { error?: string } | null,
): NoteResponse {
  if (
    !responseBody ||
    typeof responseBody !== 'object' ||
    !('id' in responseBody) ||
    !('encryptedDek' in responseBody) ||
    !('encryptedPayload' in responseBody) ||
    typeof responseBody.id !== 'string' ||
    typeof responseBody.createdAt !== 'string' ||
    typeof responseBody.updatedAt !== 'string' ||
    !isWrappedDekPayload(responseBody.encryptedDek) ||
    !isEncryptedPayload(responseBody.encryptedPayload)
  ) {
    throw new Error('The backend returned an invalid note payload.');
  }

  return {
    createdAt: responseBody.createdAt,
    encryptedDek: responseBody.encryptedDek,
    encryptedPayload: responseBody.encryptedPayload,
    id: responseBody.id,
    updatedAt: responseBody.updatedAt,
  };
}

function isWrappedDekPayload(value: unknown): value is KekAsymmetricDekEncryptedPayload['encryptedDek'] {
  return !!value &&
    typeof value === 'object' &&
    'algorithm' in value &&
    'kemCiphertextHex' in value &&
    'kekPublicKey' in value &&
    'nonceHex' in value &&
    'userId' in value &&
    'version' in value &&
    'wrappedDekHex' in value &&
    typeof value.algorithm === 'string' &&
    typeof value.kemCiphertextHex === 'string' &&
    typeof value.kekPublicKey === 'string' &&
    typeof value.nonceHex === 'string' &&
    typeof value.userId === 'string' &&
    typeof value.version === 'number' &&
    typeof value.wrappedDekHex === 'string';
}

function isEncryptedPayload(value: unknown): value is KekAsymmetricDekEncryptedPayload['encryptedPayload'] {
  return !!value &&
    typeof value === 'object' &&
    'algorithm' in value &&
    'ciphertextHex' in value &&
    'nonceHex' in value &&
    'version' in value &&
    typeof value.algorithm === 'string' &&
    typeof value.ciphertextHex === 'string' &&
    typeof value.nonceHex === 'string' &&
    typeof value.version === 'number';
}

function readErrorMessage(
  responseBody: NoteResponse | NoteResponse[] | { error?: string } | boolean | null,
) {
  return responseBody &&
    typeof responseBody === 'object' &&
    !Array.isArray(responseBody) &&
    'error' in responseBody &&
    typeof responseBody.error === 'string'
    ? responseBody.error
    : 'The backend rejected the note request.';
}

function buildApiUrl(baseUrl: string, path: string) {
  const normalizedBaseUrl = baseUrl.trim().replace(/\/+$/, '');

  if (!normalizedBaseUrl) {
    throw new Error('Set API_BASE_URL for the web app before syncing notes.');
  }

  return `${normalizedBaseUrl}${path}`;
}

function buildNotePath(noteId: string) {
  const normalizedNoteId = noteId.trim();

  if (!normalizedNoteId) {
    throw new Error('Provide a note id before sending a note request.');
  }

  return `/api/notes/${encodeURIComponent(normalizedNoteId)}`;
}

function withResponseStatus(error: Error, status: number) {
  return Object.assign(error, { status });
}