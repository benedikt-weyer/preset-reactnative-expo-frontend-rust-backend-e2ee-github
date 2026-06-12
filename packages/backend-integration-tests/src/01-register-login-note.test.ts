import { describe, it } from 'vitest';

import {
  runRegisterLoginNoteFlow,
  useIntegrationSuite,
} from './integration-support';

useIntegrationSuite();

describe('register login note flow', () => {
  it('registers, logs in, creates a note, and persists the encrypted note payload', async () => {
    await runRegisterLoginNoteFlow();
  });
});