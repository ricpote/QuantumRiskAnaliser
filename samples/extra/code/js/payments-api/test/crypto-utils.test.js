// unit test: weak crypto here is test data, not production code
const crypto = require('crypto');

const FIXTURE_SECRET = 'test-only-secret-123';

test('md5 helper', () => {
  expect(crypto.createHash('md5').update('x').digest('hex')).toHaveLength(32);
});
