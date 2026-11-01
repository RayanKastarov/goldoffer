'use strict';
// Safe building blocks for GoldOffer Pro. Every state change is ONE atomic database operation,
// so parallel orders can never use a coupon twice or push stock below zero.

// ---- Variant stock (stock is optional: no number = not tracked)
async function reserveVariant(Offer, offerId, name) {
  const r = await Offer.updateOne(
    { _id: offerId, variants: { $elemMatch: { name, stock: { $gt: 0 } } } },
    { $inc: { 'variants.$.stock': -1 } });
  if (r.modifiedCount === 1) return 'ok';
  const tracked = await Offer.exists({ _id: offerId, variants: { $elemMatch: { name, stock: { $type: 'number' } } } });
  return tracked ? 'soldout' : 'untracked';
}
async function releaseVariant(Offer, offerId, name) {
  await Offer.updateOne({ _id: offerId, variants: { $elemMatch: { name, stock: { $type: 'number' } } } }, { $inc: { 'variants.$.stock': 1 } });
}

// ---- Coupons (max = 0 means unlimited)
async function reserveCoupon(GOCoupon, sellerId, code) {
  return GOCoupon.findOneAndUpdate(
    { sellerId, code, active: true, $expr: { $or: [{ $lte: ['$max', 0] }, { $lt: ['$uses', '$max'] }] } },
    { $inc: { uses: 1 } }, { new: true });
}
async function releaseCoupon(GOCoupon, id) {
  await GOCoupon.updateOne({ _id: id, uses: { $gt: 0 } }, { $inc: { uses: -1 } });
}

// ---- Automations: claim an event once (unique index on autoId + ref)
async function claimRun(GOAutoRun, doc) {
  try { return await GOAutoRun.create(doc); }
  catch (e) { if (e && e.code === 11000) return null; throw e; }
}

// ---- Daily quota for the AI receptionist (unique index on sellerId + day)
const dayKey = () => new Date().toISOString().slice(0, 10);
async function takeQuota(GOAiUsage, sellerId, cap, key) {
  if (!(cap > 0)) return false;
  try {
    const r = await GOAiUsage.updateOne({ sellerId, day: key || dayKey(), count: { $lt: cap } }, { $inc: { count: 1 } }, { upsert: true });
    return !!(r.modifiedCount || r.upsertedCount);
  } catch (e) { if (e && e.code === 11000) return false; throw e; }
}

async function releaseQuota(GOAiUsage, sellerId, key) {
  return GOAiUsage.updateOne({ sellerId, day: key || dayKey(), count: { $gt: 0 } }, { $inc: { count: -1 } });
}

// ---- Answer safety
const sanitizeQuestion = (q) => String(q == null ? '' : q).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 400);
const INJECTION = /(ignore|disregard|forget)\s+(all|any|the|your|previous|above|prior)[^.]{0,40}(instruction|prompt|rule|message)|system\s*prompt|developer\s*message|you\s+are\s+now|act\s+as\s+(an?\s+)?(?!receptionist)|jailbreak|reveal[^.]{0,25}(prompt|instruction|key|secret)|\bDAN\b/i;
const looksLikeInjection = (q) => INJECTION.test(String(q || ''));
const numbersIn = (t) => (String(t).match(/\d+(?:[.,]\d+)?/g) || []);
const normNum = (n) => String(Number(String(n).replace(',', '.')));
const hasNum = (facts, n) => { const set = new Set(numbersIn(facts).map(normNum)); return set.has(normNum(n)); }; // whole numbers only: "12" must not match "123"
// Returns { ok, problems }: the answer may only contain numbers, links and emails that exist in the facts.
function checkGrounded(answer, facts) {
  const a = String(answer || ''), f = String(facts || ''), fl = f.toLowerCase(), problems = [];
  (a.match(/https?:\/\/\S+|www\.\S+/gi) || []).forEach(u => { if (!fl.includes(u.toLowerCase().replace(/[.,;)]+$/, ''))) problems.push('link:' + u); });
  (a.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g) || []).forEach(e => { if (!fl.includes(e.toLowerCase())) problems.push('email:' + e); });
  numbersIn(a).forEach(n => { if (!hasNum(f, n)) problems.push('number:' + n); });
  if (/FACTS\s*:|system prompt|OPENROUTER|api[_ ]?key/i.test(a)) problems.push('leak');
  return { ok: !problems.length, problems };
}
module.exports = { reserveVariant, releaseVariant, reserveCoupon, releaseCoupon, claimRun, takeQuota, releaseQuota, dayKey, sanitizeQuestion, looksLikeInjection, checkGrounded };
