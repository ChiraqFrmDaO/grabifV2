const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is required.');
  console.log('Usage: DATABASE_URL="postgresql://..." node make-admin.js THD');
  process.exit(1);
}

async function makeAdmin(username) {
  const pool = new Pool({ connectionString: DATABASE_URL });
  try {
    const result = await pool.query(
      'UPDATE users SET role = $1 WHERE username = $2 RETURNING *',
      ['admin', username]
    );
    if (result.rows.length > 0) {
      console.log(`✅ User "${username}" is nu admin!`);
      console.log(`User: ${result.rows[0].username}, Role: ${result.rows[0].role}`);
    } else {
      console.log(`❌ User "${username}" niet gevonden.`);
    }
  } catch (err) {
    console.error('❌ Fout:', err.message);
  } finally {
    await pool.end();
  }
}

const username = process.argv[2] || 'THD';
makeAdmin(username);
