export type BaseAuthApiRequest = {
  baseUrl: string;
  email: string;
};

type AuthenticatedApiRequest = {
  baseUrl: string;
  token: string;
};

export type RefreshSessionApiRequest = {
  baseUrl: string;
  refreshToken: string;
};

export type KekMetadata = {
  kekEpochVersion: number;
  kekPublicKey: string;
};

export type LoginApiRequest = BaseAuthApiRequest & {
  authKey: string;
};

export type RegisterApiRequest = LoginApiRequest & {
  kekPublicKey: string;
  saltHex: string;
};

export type AuthApiResponse = {
  kekMetadatas: KekMetadata[];
  refreshToken: string;
  token: string;
  user: {
    email: string;
    id: string;
  };
};

export type PasswordSaltResponse = {
  kekMetadatas: KekMetadata[];
  saltHex: string;
};

export type RotatePasswordApiRequest = AuthenticatedApiRequest & {
  kekPublicKey: string;
  newAuthKey: string;
};

export type KekMigrationStatusResponse = {
  allDeksUseLatestKek: boolean;
  latestKekDekCount: number;
  latestKekEpochVersion: number;
  latestKekPublicKey: string;
  pendingDekCount: number;
  totalDekCount: number;
};

export async function fetchPasswordSalt(request: BaseAuthApiRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/auth/salt'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email: request.email,
    }),
  });

  const responseBody = (await response.json().catch(() => null)) as
    | PasswordSaltResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw new Error(readErrorMessage(responseBody));
  }

  if (!isPasswordSaltResponse(responseBody)) {
    throw new Error('The backend did not return a password salt.');
  }

  return responseBody;
}

export async function loginRequest(request: LoginApiRequest) {
  return postAuthRequest('/api/auth/login', request);
}

export async function refreshSessionRequest(request: RefreshSessionApiRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/auth/refresh'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      refreshToken: request.refreshToken,
    }),
  });

  const responseBody = (await response.json().catch(() => null)) as
    | AuthApiResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  if (!isAuthApiResponse(responseBody)) {
    throw new Error('The backend response was incomplete.');
  }

  return responseBody;
}

export async function registerRequest(request: RegisterApiRequest) {
  return postAuthRequest('/api/auth/register', request);
}

export async function rotatePasswordRequest(request: RotatePasswordApiRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/auth/rotate-password'), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${request.token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      kekPublicKey: request.kekPublicKey,
      newAuthKey: request.newAuthKey,
    }),
  });

  const responseBody = (await response.json().catch(() => null)) as
    | AuthApiResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  if (!isAuthApiResponse(responseBody)) {
    throw new Error('The backend response was incomplete.');
  }

  return responseBody;
}

export async function fetchKekMigrationStatus(request: AuthenticatedApiRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/auth/kek-status'), {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${request.token}`,
    },
  });

  const responseBody = (await response.json().catch(() => null)) as
    | KekMigrationStatusResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  if (!isKekMigrationStatusResponse(responseBody)) {
    throw new Error('The backend did not return a KEK migration status.');
  }

  return responseBody;
}

async function postAuthRequest(
  path: string,
  request: LoginApiRequest | RegisterApiRequest,
): Promise<AuthApiResponse> {
  const response = await fetch(buildApiUrl(request.baseUrl, path), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      authKey: request.authKey,
      email: request.email,
      ...('kekPublicKey' in request ? { kekPublicKey: request.kekPublicKey } : {}),
      ...('saltHex' in request ? { saltHex: request.saltHex } : {}),
    }),
  });

  const responseBody = (await response.json().catch(() => null)) as
    | AuthApiResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  if (!isAuthApiResponse(responseBody)) {
    throw new Error('The backend response was incomplete.');
  }

  return responseBody;
}

export function isAuthApiResponse(value: unknown): value is AuthApiResponse {
  return !!value &&
    typeof value === 'object' &&
    'token' in value &&
    'refreshToken' in value &&
    'user' in value &&
    'kekMetadatas' in value &&
    typeof value.token === 'string' &&
    typeof value.refreshToken === 'string' &&
    !!value.user &&
    typeof value.user === 'object' &&
    'email' in value.user &&
    'id' in value.user &&
    typeof value.user.email === 'string' &&
    typeof value.user.id === 'string' &&
    Array.isArray(value.kekMetadatas) &&
    value.kekMetadatas.every(isKekMetadata);
}

function isPasswordSaltResponse(value: unknown): value is PasswordSaltResponse {
  return !!value &&
    typeof value === 'object' &&
    'saltHex' in value &&
    'kekMetadatas' in value &&
    typeof value.saltHex === 'string' &&
    Array.isArray(value.kekMetadatas) &&
    value.kekMetadatas.every(isKekMetadata);
}

function isKekMetadata(value: unknown): value is KekMetadata {
  return !!value &&
    typeof value === 'object' &&
    'kekEpochVersion' in value &&
    'kekPublicKey' in value &&
    typeof value.kekEpochVersion === 'number' &&
    typeof value.kekPublicKey === 'string';
}

function isKekMigrationStatusResponse(value: unknown): value is KekMigrationStatusResponse {
  return !!value &&
    typeof value === 'object' &&
    'allDeksUseLatestKek' in value &&
    'latestKekDekCount' in value &&
    'latestKekEpochVersion' in value &&
    'latestKekPublicKey' in value &&
    'pendingDekCount' in value &&
    'totalDekCount' in value &&
    typeof value.allDeksUseLatestKek === 'boolean' &&
    typeof value.latestKekDekCount === 'number' &&
    typeof value.latestKekEpochVersion === 'number' &&
    typeof value.latestKekPublicKey === 'string' &&
    typeof value.pendingDekCount === 'number' &&
    typeof value.totalDekCount === 'number';
}

function readErrorMessage(
  responseBody:
    | AuthApiResponse
    | KekMigrationStatusResponse
    | PasswordSaltResponse
    | { error?: string }
    | null,
) {
  return responseBody && 'error' in responseBody && typeof responseBody.error === 'string'
    ? responseBody.error
    : 'The backend rejected the request.';
}

function buildApiUrl(baseUrl: string, path: string) {
  const normalizedBaseUrl = baseUrl.trim().replace(/\/+$/, '');
  if (!normalizedBaseUrl) {
    throw new Error('Enter the backend URL before logging in.');
  }

  return `${normalizedBaseUrl}${path}`;
}

function withResponseStatus(error: Error, status: number) {
  return Object.assign(error, { status });
}
