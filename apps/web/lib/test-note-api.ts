import type { EncryptedPayload } from '@repo/e2ee-auth/web';

type AuthenticatedRequest = {
  baseUrl: string;
  token: string;
};

type SaveTestNoteRequest = AuthenticatedRequest & {
  payload: EncryptedPayload;
};

type TestNoteResponse = EncryptedPayload & {
  updatedAt: string;
};

export async function fetchTestNote(request: AuthenticatedRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/notes/test-note'), {
    headers: {
      Authorization: `Bearer ${request.token}`,
    },
    method: 'GET',
  });

  const responseBody = (await response.json().catch(() => null)) as
    | TestNoteResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw new Error(readErrorMessage(responseBody));
  }

  if (responseBody === null) {
    return null;
  }

  return validatePayload(responseBody);
}

export async function saveTestNote(request: SaveTestNoteRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/notes/test-note'), {
    body: JSON.stringify(request.payload),
    headers: {
      Authorization: `Bearer ${request.token}`,
      'Content-Type': 'application/json',
    },
    method: 'PUT',
  });

  const responseBody = (await response.json().catch(() => null)) as
    | TestNoteResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw new Error(readErrorMessage(responseBody));
  }

  return validatePayload(responseBody);
}

export async function deleteTestNote(request: AuthenticatedRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/notes/test-note'), {
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
    throw new Error(readErrorMessage(responseBody));
  }
}

function validatePayload(
  responseBody: TestNoteResponse | { error?: string } | null,
): EncryptedPayload {
  if (
    !responseBody ||
    typeof responseBody !== 'object' ||
    !('algorithm' in responseBody) ||
    typeof responseBody.algorithm !== 'string' ||
    typeof responseBody.ciphertextHex !== 'string' ||
    typeof responseBody.nonceHex !== 'string' ||
    typeof responseBody.version !== 'number'
  ) {
    throw new Error('The backend returned an invalid encrypted note payload.');
  }

  return {
    algorithm: responseBody.algorithm,
    ciphertextHex: responseBody.ciphertextHex,
    nonceHex: responseBody.nonceHex,
    version: responseBody.version,
  };
}

function readErrorMessage(
  responseBody: TestNoteResponse | { error?: string } | boolean | null,
) {
  return responseBody &&
    typeof responseBody === 'object' &&
    'error' in responseBody &&
    typeof responseBody.error === 'string'
    ? responseBody.error
    : 'The backend rejected the encrypted note request.';
}

function buildApiUrl(baseUrl: string, path: string) {
  const normalizedBaseUrl = baseUrl.trim().replace(/\/+$/, '');

  if (!normalizedBaseUrl) {
    throw new Error('Set API_BASE_URL for the web app before syncing notes.');
  }

  return `${normalizedBaseUrl}${path}`;
}