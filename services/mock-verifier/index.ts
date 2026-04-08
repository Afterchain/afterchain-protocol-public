// THIS IS A MOCK. NOT FOR PRODUCTION USE.
// Contains no proprietary oracle logic.

export function mockVerify() {
  return {
    status: 'ok',
    attestation: 'mock-only',
    note: 'This is a non-functional demo stub.',
  };
}
