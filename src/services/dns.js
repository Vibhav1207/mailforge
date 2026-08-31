const dns = require('dns').promises;

// Verify a domain's DNS records
async function verifyDomain(domainDoc) {
  const errors = [];
  let verificationFound = false;
  let spfFound = false;
  let dkimFound = false;
  let dmarcFound = false;

  // 1. Check TXT records for verification token
  try {
    const txtRecords = await dns.resolveTxt(domainDoc.domain);
    for (const record of txtRecords) {
      const txtValue = record.join('');
      if (domainDoc.verification_token && txtValue.includes(`mailforge-verification=${domainDoc.verification_token}`)) {
        verificationFound = true;
        break;
      }
    }
  } catch (err) {
    if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
      errors.push('Domain does not exist in DNS');
    } else {
      errors.push(`DNS lookup failed: ${err.message}`);
    }
  }

  // 2. Check SPF record
  try {
    const txtRecords = await dns.resolveTxt(domainDoc.domain);
    for (const record of txtRecords) {
      const txtValue = record.join('');
      if (txtValue.includes('v=spf1') && txtValue.includes('mailforge')) {
        spfFound = true;
        break;
      }
    }
  } catch {
    // SPF check is non-critical
  }

  // 3. Check DKIM record
  try {
    const dkimDomain = `${domainDoc.dkim_selector || 'mailforge'}.${domainDoc.domain}`;
    const dkimRecords = await dns.resolveTxt(dkimDomain);
    for (const record of dkimRecords) {
      const txtValue = record.join('');
      if (txtValue.includes('v=DKIM1')) {
        dkimFound = true;
        break;
      }
    }
  } catch {
    errors.push('DKIM record not found');
  }

  // 4. Check DMARC record
  try {
    const dmarcDomain = `_dmarc.${domainDoc.domain}`;
    const dmarcRecords = await dns.resolveTxt(dmarcDomain);
    for (const record of dmarcRecords) {
      const txtValue = record.join('');
      if (txtValue.includes('v=DMARC1')) {
        dmarcFound = true;
        break;
      }
    }
  } catch {
    // DMARC is recommended but not required for basic verification
  }

  // Domain is verified if verification token found, or at least some DNS records configured
  const passed = verificationFound || spfFound || dkimFound || dmarcFound;

  return { passed, errors, verificationFound, spfFound, dkimFound, dmarcFound };
}

module.exports = { verifyDomain };
