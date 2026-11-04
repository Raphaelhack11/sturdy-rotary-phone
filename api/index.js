const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
if (!JWT_SECRET || !DATABASE_URL) console.error('Missing env vars: JWT_SECRET / DATABASE_URL');

const sql = neon(DATABASE_URL);

/* ============================================================
   SEED COURSES — real LASU Mathematical Education 100-level list
   ============================================================ */
const SEED_COURSES = [
  { code: 'GNS 111', title: 'Communication in English, Use of Library and ICT', units: 2 },
  { code: 'EDU 101', title: 'Introduction to Teaching and Foundations of Education', units: 2 },
  { code: 'SED 101', title: 'Introduction to Science and Mathematics Education', units: 2 },
  { code: 'MAT 101', title: 'Elementary Mathematics I (Algebra and Trigonometry)', units: 2 },
  { code: 'EDM 111', title: 'Principles and Practice of Educational Management', units: 2 },
  { code: 'EST 151', title: 'Teaching Difficult Concepts in Primary and Junior Secondary School Mathematics', units: 2 },
  { code: 'EST 153', title: 'Curriculum Evolution in Mathematics Education', units: 2 },
  { code: 'EST 155', title: 'School Attachment Programme', units: 2 },
  { code: 'EDT 105', title: 'Teaching and Learning in the Digital Age', units: 2 },
  { code: 'MAT 161', title: 'Descriptive Statistics', units: 2 }
];

const parseCookies = (h = '') => Object.fromEntries(
  h.split(';').filter(Boolean).map(c => {
    const [k, ...v] = c.trim().split('=');
    return [k, v.join('=')];
  })
);

async function requireAdmin(req) {
  const token = parseCookies(req.headers.cookie || '').admin_token;
  if (!token) return null;
  try {
    const p = jwt.verify(token, JWT_SECRET);
    return p.role === 'admin' ? p : null;
  } catch { return null; }
}

const send = (res, status, body, headers = {}) => {
  res.status(status).setHeader('Content-Type', 'application/json');
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
};

/* ---------- schema + seed ---------- */
async function ensureSchema() {
  await sql`
    CREATE TABLE IF NOT EXISTS courses (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      code TEXT NOT NULL UNIQUE,
      lecturer TEXT DEFAULT '',
      units INTEGER DEFAULT 2,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;
  await sql`ALTER TABLE courses ADD COLUMN IF NOT EXISTS units INTEGER DEFAULT 2`;

  await sql`
    CREATE TABLE IF NOT EXISTS assignments (
      id SERIAL PRIMARY KEY,
      course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      instructions TEXT NOT NULL,
      date_assigned DATE NOT NULL,
      deadline TIMESTAMPTZ NOT NULL,
      submission_method TEXT NOT NULL,
      notes TEXT DEFAULT '',
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;

  const [{ count }] = await sql`SELECT COUNT(*)::int AS count FROM courses`;
  if (count === 0) {
    for (const c of SEED_COURSES) {
      await sql`
        INSERT INTO courses (title, code, lecturer, units)
        VALUES (${c.title}, ${c.code}, ${''}, ${c.units})
        ON CONFLICT (code) DO NOTHING
      `;
    }
    console.log('Seeded', SEED_COURSES.length, 'default courses');
  }
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.status(204).end();

  try { await ensureSchema(); }
  catch (e) { console.error('Schema error:', e); return send(res, 500, { error: 'DB unavailable' }); }

  const path = (new URL(req.url, `https://${req.headers.host}`).pathname).replace(/^\/api/, '') || '/';

  /* ---------- PUBLIC READ ---------- */
  if (req.method === 'GET' && path === '/data') {
    const courses = await sql`SELECT id, title, code, lecturer, units FROM courses ORDER BY code`;
    const assignments = await sql`
      SELECT a.id, a.course_id, a.title, a.instructions, a.date_assigned, a.deadline,
             a.submission_method, a.notes, a.published, a.created_at,
             c.code AS course_code, c.title AS course_title, c.units AS course_units
      FROM assignments a JOIN courses c ON c.id = a.course_id
      WHERE a.published = TRUE ORDER BY a.deadline ASC`;
    return send(res, 200, { courses, assignments });
  }

  /* ---------- AUTH ---------- */
  if (req.method === 'POST' && path === '/admin/login') {
    const { email, password } = req.body || {};
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminHash = process.env.ADMIN_PASSWORD_HASH;
    if (!adminEmail || !adminHash) return send(res, 500, { error: 'Admin credentials not configured on server' });
    if (email !== adminEmail) return send(res, 401, { error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, adminHash);
    if (!ok) return send(res, 401, { error: 'Invalid credentials' });
    const token = jwt.sign({ role: 'admin', email }, JWT_SECRET, { expiresIn: '8h' });
    return send(res, 200, { ok: true }, {
      'Set-Cookie': `admin_token=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`
    });
  }

  if (req.method === 'POST' && path === '/admin/logout') {
    return send(res, 200, { ok: true }, {
      'Set-Cookie': 'admin_token=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
    });
  }

  if (req.method === 'GET' && path === '/admin/me') {
    const a = await requireAdmin(req);
    return a ? send(res, 200, { email: a.email }) : send(res, 401, { error: 'Unauthorized' });
  }

  if (req.method === 'GET' && path === '/admin/data') {
    const a = await requireAdmin(req);
    if (!a) return send(res, 401, { error: 'Unauthorized' });
    const courses = await sql`SELECT * FROM courses ORDER BY code`;
    const assignments = await sql`
      SELECT a.*, c.code AS course_code, c.title AS course_title
      FROM assignments a JOIN courses c ON c.id = a.course_id
      ORDER BY a.created_at DESC`;
    return send(res, 200, { courses, assignments });
  }

  /* ---------- COURSES CRUD ---------- */
  if (req.method === 'POST' && path === '/admin/courses') {
    if (!(await requireAdmin(req))) return send(res, 401, { error: 'Unauthorized' });
    const { title, code, lecturer, units } = req.body || {};
    if (!title || !code) return send(res, 400, { error: 'Title and code required' });
    try {
      const [row] = await sql`
        INSERT INTO courses (title, code, lecturer, units)
        VALUES (${title}, ${code.toUpperCase()}, ${lecturer || ''}, ${parseInt(units) || 2})
        RETURNING *`;
      return send(res, 201, row);
    } catch (e) {
      if (String(e.message).includes('unique')) return send(res, 409, { error: 'Course code already exists' });
      return send(res, 500, { error: 'Could not create course' });
    }
  }

  if (req.method === 'PUT' && path.startsWith('/admin/courses/')) {
    if (!(await requireAdmin(req))) return send(res, 401, { error: 'Unauthorized' });
    const id = parseInt(path.split('/').pop());
    const { title, code, lecturer, units } = req.body || {};
    if (!title || !code) return send(res, 400, { error: 'Title and code required' });
    try {
      const [row] = await sql`
        UPDATE courses SET title = ${title}, code = ${code.toUpperCase()},
          lecturer = ${lecturer || ''}, units = ${parseInt(units) || 2}
        WHERE id = ${id} RETURNING *`;
      return row ? send(res, 200, row) : send(res, 404, { error: 'Not found' });
    } catch (e) {
      if (String(e.message).includes('unique')) return send(res, 409, { error: 'Course code already exists' });
      return send(res, 500, { error: 'Could not update' });
    }
  }

  if (req.method === 'DELETE' && path.startsWith('/admin/courses/')) {
    if (!(await requireAdmin(req))) return send(res, 401, { error: 'Unauthorized' });
    await sql`DELETE FROM courses WHERE id = ${parseInt(path.split('/').pop())}`;
    return send(res, 200, { ok: true });
  }

  /* ---------- ASSIGNMENTS CRUD ---------- */
  if (req.method === 'POST' && path === '/admin/assignments') {
    if (!(await requireAdmin(req))) return send(res, 401, { error: 'Unauthorized' });
    const b = req.body || {};
    if (!b.course_id || !b.title || !b.instructions || !b.date_assigned || !b.deadline || !b.submission_method)
      return send(res, 400, { error: 'Missing required fields' });
    const [row] = await sql`
      INSERT INTO assignments
        (course_id, title, instructions, date_assigned, deadline, submission_method, notes, published)
      VALUES (${b.course_id}, ${b.title}, ${b.instructions}, ${b.date_assigned}, ${b.deadline},
              ${b.submission_method}, ${b.notes || ''}, ${b.published === true}) RETURNING *`;
    return send(res, 201, row);
  }

  if (req.method === 'PUT' && path.startsWith('/admin/assignments/')) {
    if (!(await requireAdmin(req))) return send(res, 401, { error: 'Unauthorized' });
    const id = parseInt(path.split('/').pop());
    const b = req.body || {};
    if (!b.course_id || !b.title || !b.instructions || !b.date_assigned || !b.deadline || !b.submission_method)
      return send(res, 400, { error: 'Missing required fields' });
    const [row] = await sql`
      UPDATE assignments SET course_id = ${b.course_id}, title = ${b.title},
        instructions = ${b.instructions}, date_assigned = ${b.date_assigned},
        deadline = ${b.deadline}, submission_method = ${b.submission_method},
        notes = ${b.notes || ''}, published = ${b.published === true}
      WHERE id = ${id} RETURNING *`;
    return row ? send(res, 200, row) : send(res, 404, { error: 'Not found' });
  }

  if (req.method === 'DELETE' && path.startsWith('/admin/assignments/')) {
    if (!(await requireAdmin(req))) return send(res, 401, { error: 'Unauthorized' });
    await sql`DELETE FROM assignments WHERE id = ${parseInt(path.split('/').pop())}`;
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: 'Not found' });
};
