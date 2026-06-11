export type BaseAuthApiRequest = {
  baseUrl: string;
  email: string;
};

export type LoginApiRequest = BaseAuthApiRequest & {
  authKey: string;
};

export type RegisterApiRequest = LoginApiRequest & {
  saltHex: string;
};

export type AuthApiResponse = {
  refreshToken: string;
  token: string;
  user: {
    email: string;
    id: string;
  };
};

type PasswordSaltResponse = {
  saltHex: string;
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

  if (
    !responseBody ||
    !(responseBody as PasswordSaltResponse).saltHex ||
    typeof (responseBody as PasswordSaltResponse).saltHex !== 'string'
  ) {
    throw new Error('The backend did not return a password salt.');
  }

  return (responseBody as PasswordSaltResponse).saltHex;
}

export async function loginRequest(request: LoginApiRequest) {
  return postAuthRequest('/api/auth/login', request);
}

export async function registerRequest(request: RegisterApiRequest) {
  return postAuthRequest('/api/auth/register', request);
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
      ...('saltHex' in request ? { saltHex: request.saltHex } : {}),
    }),
  });

  const responseBody = (await response.json().catch(() => null)) as
    | AuthApiResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    throw new Error(readErrorMessage(responseBody));
  }

  if (
    !responseBody ||
    !(responseBody as AuthApiResponse).token ||
    !(responseBody as AuthApiResponse).refreshToken
  ) {
    throw new Error('The backend response was incomplete.');
  }

  return responseBody as AuthApiResponse;
}

function readErrorMessage(
  responseBody:
    | AuthApiResponse
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
