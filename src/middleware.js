const { ObjectId } = require('mongodb');
const { users, workspaces, domains } = require('./db');

// Get current user from session
async function getCurrentUser(userId) {
  if (!userId) return null;
  try {
    return await users.findOne({ _id: new ObjectId(userId) });
  } catch {
    return null;
  }
}

// Get or create default workspace for user
async function getOrCreateWorkspace(userId) {
  let workspace = await workspaces.findOne({ owner_id: userId });
  if (workspace) return workspace;

  const user = await users.findOne({ _id: new ObjectId(userId) });
  if (!user) return null;

  let slug = (user.name || 'workspace').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 20) || 'workspace';
  let baseSlug = slug;
  let counter = 1;
  while (await workspaces.findOne({ slug })) {
    slug = `${baseSlug}${counter}`;
    counter++;
  }

  const result = await workspaces.insertOne({
    name: `${user.name}'s Workspace`,
    slug,
    owner_id: userId,
    plan: 'free',
    created_at: new Date()
  });

  return workspaces.findOne({ _id: result.insertedId });
}

// Auto-create or find default user (no auth required)
async function ensureDefaultUser() {
  let user = await users.findOne({ email: 'admin@mailforge.local' });
  if (user) return user;

  const result = await users.insertOne({
    name: 'Admin',
    email: 'admin@mailforge.local',
    password_hash: '',
    email_verified: true,
    created_at: new Date()
  });
  return users.findOne({ _id: result.insertedId });
}

// Auth-required middleware — bypassed, auto-logs in
function requireAuth(req, res, next) {
  next();
}

// Workspace context middleware — auto-creates default user/workspace
async function loadWorkspace(req, res, next) {
  let user;
  if (req.session && req.session.userId) {
    user = await getCurrentUser(req.session.userId);
  }
  if (!user) {
    user = await ensureDefaultUser();
    req.session.userId = user._id.toString();
  }
  const workspace = await getOrCreateWorkspace(user._id.toString());
  if (!workspace) {
    return res.status(500).render('login', { flash: { type: 'danger', message: 'Failed to create workspace.' } });
  }
  res.locals.workspace = workspace;
  res.locals.user = user;
  res.locals.currentPath = req.path;
  next();
}

// Flash message middleware
function flashMessages(req, res, next) {
  res.locals.flash = req.session.flash || {};
  delete req.session.flash;
  next();
}

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

module.exports = { getCurrentUser, getOrCreateWorkspace, requireAuth, loadWorkspace, flashMessages, setFlash };
