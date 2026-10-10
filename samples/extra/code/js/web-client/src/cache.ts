// Cache keys use our own helper (./hash-utils), not node:crypto
import { createHash } from './hash-utils';

export const cacheKey = (url: string): string => createHash('md5', url);
