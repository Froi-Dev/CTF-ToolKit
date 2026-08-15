import assert from 'node:assert/strict';
import test from 'node:test';

import {
  availableIdentityPivots,
  commonDorks,
  googleSearchUrl,
  identityPivots,
  normalizeDorkDomain,
} from '../js/modules/osint-dorks.ts';

const context = {
  username: 'alice',
  name: 'Alice Example',
  subject: 'Alice Example',
  email: 'alice@example.com',
  afterDate: '2022-01-01',
  beforeDate: '2027-01-01',
};

function generatedQueries() {
  return [
    ...commonDorks.map(item => item.query('example.com')),
    ...identityPivots.map(item => item.destination(context).display),
  ].filter(value => value.includes(':') || value.includes('"'));
}

test('generated dorks keep paths out of site operands', () => {
  for (const query of generatedQueries()) {
    const operands = [...query.matchAll(/\bsite:([^\s)]+)/g)].map(match => match[1]);
    for (const operand of operands) {
      assert.equal(operand.includes('/'), false, query);
      assert.equal(operand.startsWith('*.'), false, query);
    }
  }
});

test('generated dorks avoid deprecated and unsupported patterns', () => {
  for (const query of generatedQueries()) {
    assert.doesNotMatch(query, /\b\d{4}\.\.\d{4}\b/);
    assert.equal(query.includes('author:'), false, query);
    assert.equal(query.includes('filetype:pdf author'), false, query);
    assert.doesNotMatch(query, /\b(?:site|filetype|inurl|intitle|after|before):\s/);
  }
});

test('date pivot uses explicit after and before dates', () => {
  const pivot = identityPivots.find(item => item.id === 'dated-posts');
  assert.ok(pivot);
  assert.equal(
    pivot.destination(context).display,
    '"alice" after:2022-01-01 before:2027-01-01',
  );
});

test('email-only pivots are omitted until an email is supplied', () => {
  const withoutEmail = availableIdentityPivots({ ...context, email: '' });
  assert.equal(withoutEmail.some(item => item.requires === 'email'), false);
  assert.equal(availableIdentityPivots(context).some(item => item.requires === 'email'), true);
});

test('domain normalization returns a hostname or rejects malformed input', () => {
  assert.equal(normalizeDorkDomain('https://www.Example.com/admin'), 'example.com');
  assert.equal(normalizeDorkDomain('site: example.com'), '');
  assert.equal(normalizeDorkDomain('not-a-domain'), '');
});

test('Google links encode the query as one q parameter', () => {
  const url = new URL(googleSearchUrl('site:example.com inurl:"/admin"'));
  assert.equal(url.origin, 'https://www.google.com');
  assert.equal(url.searchParams.get('q'), 'site:example.com inurl:"/admin"');
});
