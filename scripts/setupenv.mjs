import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PLACEHOLDER_SECRETS = new Map([
  ['JWT_SECRET', 'change-me-for-non-local-use'],
]);

const LEGACY_ENV_KEYS = new Map([
  ['JWT_TTL_MINUTES', 'JWT_TTL_HOURS'],
  ['JWT_REFRESH_TTL_MINUTES', 'JWT_REFRESH_TTL_HOURS'],
]);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

async function findEnvExamples(rootDir) {
  const results = [];
  const ignoredDirectories = new Set([
    '.git',
    '.next',
    '.turbo',
    '.venv',
    'build',
    'dist',
    'node_modules',
    'site',
    'target',
  ]);

  async function walk(currentDir) {
    const entries = await readdir(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (ignoredDirectories.has(entry.name)) {
          continue;
        }

        await walk(path.join(currentDir, entry.name));
        continue;
      }

      if (entry.isFile() && entry.name === '.env.example') {
        results.push(path.join(currentDir, entry.name));
      }
    }
  }

  await walk(rootDir);
  return results;
}

function parseEnv(content) {
  const values = new Map();

  for (const line of content.split(/\r?\n/)) {
    if (!line || line.trimStart().startsWith('#')) {
      continue;
    }

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim();
    const value = line.slice(separatorIndex + 1);
    values.set(key, value);
  }

  return values;
}

function parseEnvTemplate(content) {
  return content.replace(/\r\n/g, '\n').split('\n').map((line) => {
    if (!line || line.trimStart().startsWith('#')) {
      return { type: 'raw', raw: line };
    }

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1) {
      return { type: 'raw', raw: line };
    }

    return {
      type: 'entry',
      key: line.slice(0, separatorIndex).trim(),
      value: line.slice(separatorIndex + 1),
    };
  });
}

function generateSecret() {
  return randomBytes(48).toString('base64url');
}

function applyGeneratedSecrets(content) {
  const envValues = parseEnv(content);
  let nextContent = content;
  let changed = false;

  for (const [key, placeholder] of PLACEHOLDER_SECRETS) {
    const currentValue = envValues.get(key);
    if (!currentValue || currentValue !== placeholder) {
      continue;
    }

    const generatedValue = generateSecret();
    const pattern = new RegExp(`^${key}=${escapeRegExp(placeholder)}$`, 'm');
    nextContent = nextContent.replace(pattern, `${key}=${generatedValue}`);
    changed = true;
  }

  return { content: nextContent, changed };
}

function resolveEnvValue(key, currentValue, fallbackValue) {
  const placeholder = PLACEHOLDER_SECRETS.get(key);
  const value = currentValue ?? fallbackValue;

  if (placeholder && value === placeholder) {
    return generateSecret();
  }

  return value;
}

function getExistingEnvValue(existingValues, key) {
  const currentValue = existingValues.get(key);
  if (currentValue !== undefined) {
    return currentValue;
  }

  const legacyKey = LEGACY_ENV_KEYS.get(key);
  return legacyKey ? existingValues.get(legacyKey) : undefined;
}

function syncEnvContent(exampleContent, existingContent) {
  const templateLines = parseEnvTemplate(exampleContent);
  const existingValues = parseEnv(existingContent);

  return matchTemplateTrailingNewline(
    exampleContent,
    templateLines
      .map((line) => {
        if (line.type !== 'entry') {
          return line.raw;
        }

        const value = resolveEnvValue(
          line.key,
          getExistingEnvValue(existingValues, line.key),
          line.value,
        );

        return `${line.key}=${value}`;
      })
      .join('\n'),
  );
}

function matchTemplateTrailingNewline(template, content) {
  if (!template.endsWith('\n') || content.endsWith('\n')) {
    return content;
  }

  return `${content}\n`;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function ensureEnvFile(examplePath) {
  const envPath = path.join(path.dirname(examplePath), '.env');
  const template = await readFile(examplePath, 'utf8');

  if (existsSync(envPath)) {
    const currentContent = await readFile(envPath, 'utf8');
    const nextContent = syncEnvContent(template, currentContent);

    if (nextContent === currentContent) {
      return { envPath, action: 'skipped' };
    }

    await writeFile(envPath, nextContent, 'utf8');
    return { envPath, action: 'synced' };
  }

  const { content } = applyGeneratedSecrets(template);
  await mkdir(path.dirname(envPath), { recursive: true });
  await writeFile(envPath, content, 'utf8');

  return { envPath, action: 'created' };
}

async function main() {
  const examplePaths = await findEnvExamples(repoRoot);

  if (examplePaths.length === 0) {
    console.log('No .env.example files found.');
    return;
  }

  const results = [];
  for (const examplePath of examplePaths.sort()) {
    results.push(await ensureEnvFile(examplePath));
  }

  for (const result of results) {
    const relativePath = path.relative(repoRoot, result.envPath);
    if (result.action === 'created') {
      console.log(`created ${relativePath}`);
    } else if (result.action === 'synced') {
      console.log(`synced ${relativePath}`);
    } else {
      console.log(`kept existing ${relativePath}`);
    }
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});