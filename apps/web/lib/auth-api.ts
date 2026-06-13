export type BaseAuthApiRequest = {
  baseUrl: string;
  email: string;
};

export type PrincipalKind = 'user' | 'api_user';

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

export type ApiUserLoginApiRequest = {
  baseUrl: string;
  authKey: string;
  username: string;
};

export type Principal = {
  email?: string | null;
  id: string;
  kind: PrincipalKind;
  username?: string | null;
};

export type LinkedPrincipal = {
  email?: string | null;
  id: string;
  kind: PrincipalKind;
  latestKekEpochVersion: number;
  latestKekPublicKey: string;
  username?: string | null;
};

export type AuthApiResponse = {
  currentPrincipal: Principal;
  kekMetadatas: KekMetadata[];
  linkedPrincipals: LinkedPrincipal[];
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

export type WrappedDekPayload = {
  algorithm: 'ml-kem-768-encapsulated+xsalsa20-poly1305';
  kemCiphertextHex: string;
  kekPublicKey: string;
  nonceHex: string;
  userId: string;
  version: 3;
  wrappedDekHex: string;
};

export type EncryptedBlobPayload = {
  algorithm: 'xsalsa20-poly1305';
  ciphertextHex: string;
  nonceHex: string;
  version: 1;
};

export type ApiUserProvisioningStatus = {
  completedResourceCount: number;
  pendingNoteIds: string[];
  pendingResourceCount: number;
  totalResourceCount: number;
};

export type ApiUserResponse = {
  createdAt: string;
  encryptedLabel: EncryptedBlobPayload;
  encryptedLabelDek: WrappedDekPayload;
  id: string;
  latestKekEpochVersion: number;
  latestKekPublicKey: string;
  provisioning: ApiUserProvisioningStatus;
  updatedAt: string;
  username: string;
};

export type CreateApiUserApiRequest = AuthenticatedApiRequest & {
  authKey: string;
  encryptedLabel: EncryptedBlobPayload;
  encryptedLabelDeks: WrappedDekPayload[];
  id: string;
  kekPublicKey: string;
};

export type ProvisionApiUserDeksApiRequest = AuthenticatedApiRequest & {
  apiUserId: string;
  wrappedDeks: Array<{
    resourceId: string;
    wrappedDek: WrappedDekPayload;
  }>;
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

  return readAuthResponse(response);
}

export async function registerRequest(request: RegisterApiRequest) {
  return postAuthRequest('/api/auth/register', request);
}

export async function apiUserLoginRequest(request: ApiUserLoginApiRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/auth/api-users/login'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      authKey: request.authKey,
      username: request.username,
    }),
  });

  return readAuthResponse(response);
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

export async function fetchLinkedPrincipals(request: AuthenticatedApiRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/auth/linked-principals'), {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${request.token}`,
    },
  });

  const responseBody = (await response.json().catch(() => null)) as
    | LinkedPrincipal[]
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  if (!Array.isArray(responseBody) || !responseBody.every(isLinkedPrincipal)) {
    throw new Error('The backend did not return linked principal metadata.');
  }

  return responseBody;
}

export async function fetchApiUsers(request: AuthenticatedApiRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/auth/api-users'), {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${request.token}`,
    },
  });

  const responseBody = (await response.json().catch(() => null)) as
    | ApiUserResponse[]
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  if (!Array.isArray(responseBody) || !responseBody.every(isApiUserResponse)) {
    throw new Error('The backend did not return api users.');
  }

  return responseBody;
}

export async function fetchApiUser(
  request: AuthenticatedApiRequest & { apiUserId: string },
) {
  const response = await fetch(
    buildApiUrl(request.baseUrl, `/api/auth/api-users/${encodeURIComponent(request.apiUserId)}`),
    {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${request.token}`,
      },
    },
  );

  const responseBody = (await response.json().catch(() => null)) as
    | ApiUserResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  if (!isApiUserResponse(responseBody)) {
    throw new Error('The backend did not return the api user state.');
  }

  return responseBody;
}

export async function createApiUserRequest(request: CreateApiUserApiRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/auth/api-users'), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${request.token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      id: request.id,
      authKey: request.authKey,
      encryptedLabel: request.encryptedLabel,
      encryptedLabelDeks: request.encryptedLabelDeks,
      kekPublicKey: request.kekPublicKey,
    }),
  });

  return readApiUserResponse(response);
}

export async function deleteApiUserRequest(
  request: AuthenticatedApiRequest & { apiUserId: string },
) {
  const response = await fetch(
    buildApiUrl(request.baseUrl, `/api/auth/api-users/${encodeURIComponent(request.apiUserId)}`),
    {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${request.token}`,
      },
    },
  );

  const responseBody = (await response.json().catch(() => null)) as
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }
}

export async function deleteAccountRequest(request: AuthenticatedApiRequest) {
  const response = await fetch(buildApiUrl(request.baseUrl, '/api/auth/account'), {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${request.token}`,
    },
  });

  const responseBody = (await response.json().catch(() => null)) as
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }
}

export async function provisionApiUserDeksRequest(request: ProvisionApiUserDeksApiRequest) {
  const response = await fetch(
    buildApiUrl(
      request.baseUrl,
      `/api/auth/api-users/${encodeURIComponent(request.apiUserId)}/provision`,
    ),
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${request.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        wrappedDeks: request.wrappedDeks,
      }),
    },
  );

  return readApiUserResponse(response);
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

  return readAuthResponse(response);
}

function isAuthApiResponse(value: unknown): value is AuthApiResponse {
  return !!value &&
    typeof value === 'object' &&
    'currentPrincipal' in value &&
    'token' in value &&
    'refreshToken' in value &&
    'user' in value &&
    'kekMetadatas' in value &&
    'linkedPrincipals' in value &&
    typeof value.token === 'string' &&
    typeof value.refreshToken === 'string' &&
    isPrincipal(value.currentPrincipal) &&
    !!value.user &&
    typeof value.user === 'object' &&
    'email' in value.user &&
    'id' in value.user &&
    typeof value.user.email === 'string' &&
    typeof value.user.id === 'string' &&
    Array.isArray(value.linkedPrincipals) &&
    value.linkedPrincipals.every(isLinkedPrincipal) &&
    Array.isArray(value.kekMetadatas) &&
    value.kekMetadatas.every(isKekMetadata);
}

function isPrincipal(value: unknown): value is Principal {
  return !!value &&
    typeof value === 'object' &&
    'id' in value &&
    'kind' in value &&
    typeof value.id === 'string' &&
    (value.kind === 'user' || value.kind === 'api_user') &&
    (!('email' in value) || value.email === null || typeof value.email === 'string') &&
    (!('username' in value) || value.username === null || typeof value.username === 'string');
}

function isLinkedPrincipal(value: unknown): value is LinkedPrincipal {
  return isPrincipal(value) &&
    'latestKekEpochVersion' in value &&
    'latestKekPublicKey' in value &&
    typeof value.latestKekEpochVersion === 'number' &&
    typeof value.latestKekPublicKey === 'string';
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

function isEncryptedBlobPayload(value: unknown): value is EncryptedBlobPayload {
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

function isWrappedDekPayload(value: unknown): value is WrappedDekPayload {
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

function isApiUserProvisioningStatus(value: unknown): value is ApiUserProvisioningStatus {
  return !!value &&
    typeof value === 'object' &&
    'completedResourceCount' in value &&
    'pendingNoteIds' in value &&
    'pendingResourceCount' in value &&
    'totalResourceCount' in value &&
    typeof value.completedResourceCount === 'number' &&
    Array.isArray(value.pendingNoteIds) &&
    value.pendingNoteIds.every((noteId) => typeof noteId === 'string') &&
    typeof value.pendingResourceCount === 'number' &&
    typeof value.totalResourceCount === 'number';
}

function isApiUserResponse(value: unknown): value is ApiUserResponse {
  return !!value &&
    typeof value === 'object' &&
    'createdAt' in value &&
    'encryptedLabel' in value &&
    'encryptedLabelDek' in value &&
    'id' in value &&
    'latestKekEpochVersion' in value &&
    'latestKekPublicKey' in value &&
    'provisioning' in value &&
    'updatedAt' in value &&
    'username' in value &&
    typeof value.createdAt === 'string' &&
    isEncryptedBlobPayload(value.encryptedLabel) &&
    isWrappedDekPayload(value.encryptedLabelDek) &&
    typeof value.id === 'string' &&
    typeof value.latestKekEpochVersion === 'number' &&
    typeof value.latestKekPublicKey === 'string' &&
    isApiUserProvisioningStatus(value.provisioning) &&
    typeof value.updatedAt === 'string' &&
    typeof value.username === 'string';
}

async function readAuthResponse(response: Response) {
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

async function readApiUserResponse(response: Response) {
  const responseBody = (await response.json().catch(() => null)) as
    | ApiUserResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw withResponseStatus(new Error(readErrorMessage(responseBody)), response.status);
  }

  if (!isApiUserResponse(responseBody)) {
    throw new Error('The backend did not return the api user state.');
  }

  return responseBody;
}

function readErrorMessage(
  responseBody:
    | AuthApiResponse
    | ApiUserResponse
    | ApiUserResponse[]
    | LinkedPrincipal[]
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
    throw new Error('Set API_BASE_URL for the web app before logging in.');
  }

  return `${normalizedBaseUrl}${path}`;
}

function withResponseStatus(error: Error, status: number) {
  return Object.assign(error, { status });
}