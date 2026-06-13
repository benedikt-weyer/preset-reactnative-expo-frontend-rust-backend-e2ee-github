import path from 'node:path';

import { BaseSequencer, type TestSpecification } from 'vitest/node';

const ORDERED_FILES = [
  '01-register-login-note.test.ts',
  '02-password-rotation.test.ts',
  '03-api-user.test.ts',
  '04-import-export-suite.test.ts',
];

const FILE_RANK = new Map(ORDERED_FILES.map((fileName, index) => [fileName, index]));

export class OrderedIntegrationSequencer extends BaseSequencer {
  override async sort(files: TestSpecification[]) {
    const sorted = await super.sort(files);

    return [...sorted].sort((left, right) => {
      const leftRank = FILE_RANK.get(path.basename(left.moduleId)) ?? ORDERED_FILES.length;
      const rightRank = FILE_RANK.get(path.basename(right.moduleId)) ?? ORDERED_FILES.length;

      if (leftRank !== rightRank) {
        return leftRank - rightRank;
      }

      return left.moduleId.localeCompare(right.moduleId);
    });
  }
}