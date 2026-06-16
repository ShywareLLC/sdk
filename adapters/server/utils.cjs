'use strict';

function trimString(value) {
  if (value == null) return '';
  return String(value).trim();
}

function isLocalRequest(req) {
  const ip = req.ip || req.connection?.remoteAddress || '';
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1'
    || process.env.NODE_ENV === 'development';
}

function getRequestHost(req) {
  const forwarded = trimString(req.get('x-forwarded-host') || req.get('x-original-host'));
  return (forwarded || trimString(req.get('host') || req.hostname || '')).toLowerCase().split(':')[0];
}

function normalizeTenantSlug(value, fallback = 'default') {
  const normalized = trimString(value).toLowerCase().replace(/[^a-z0-9-]/g, '-');
  return normalized || fallback;
}

function normalizeAttachmentRefs(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (typeof value === 'string') return value.split('\n').map(s => s.trim()).filter(Boolean);
  return [];
}

module.exports = { trimString, isLocalRequest, getRequestHost, normalizeTenantSlug, normalizeAttachmentRefs };
