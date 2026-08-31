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

// Auth-required middleware
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.method === 'POST' && !req.xhr) {
      req.session.returnTo = req.originalUrl;
    }
    return res.redirect('/login');
  }
  next();
}

// Workspace context middleware — loads workspace into res.locals
async function loadWorkspace(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.redirect('/login');
  }
  const workspace = await getOrCreateWorkspace(req.session.userId);
  if (!workspace) {
    req.session.destroy();
    return res.redirect('/login');
  }
  const user = await getCurrentUser(req.session.userId);
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
