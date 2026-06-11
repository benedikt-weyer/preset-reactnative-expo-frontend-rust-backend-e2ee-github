export type AuthApiRequest = {
  authKey: string;
  baseUrl: string;
  email: string;
};

export type AuthApiResponse = {
  token: string;
  user: {
    email: string;
    id: string;
  };
};

export async function loginRequest(request: AuthApiRequest) {
  return postAuthRequest('/api/auth/login', request);
}

export async function registerRequest(request: AuthApiRequest) {
  return postAuthRequest('/api/auth/register', request);
}

async function postAuthRequest(
  path: string,
  request: AuthApiRequest,
): Promise<AuthApiResponse> {
  const response = await fetch(buildApiUrl(request.baseUrl, path), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      authKey: request.authKey,
      email: request.email,
    }),
  });

  const responseBody = (await response.json().catch(() => null)) as
    | AuthApiResponse
    | { error?: string }
    | null;

  if (!response.ok) {
    const errorMessage =
      responseBody && 'error' in responseBody && typeof responseBody.error === 'string'
        ? responseBody.error
        : 'The backend rejected the request.';

    throw new Error(errorMessage);
  }

  if (!responseBody || !(responseBody as AuthApiResponse).token) {
    throw new Error('The backend response was incomplete.');
  }

  return responseBody as AuthApiResponse;
}

function buildApiUrl(baseUrl: string, path: string) {
  const normalizedBaseUrl = baseUrl.trim().replace(/\/+$/, '');
  if (!normalizedBaseUrl) {
    throw new Error('Enter the backend URL before logging in.');
  }

  return `${normalizedBaseUrl}${path}`;
}
