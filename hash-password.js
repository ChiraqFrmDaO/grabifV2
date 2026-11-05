const bcrypt = require('bcrypt');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question('Voer je wachtwoord in: ', async (password) => {
  if (!password) {
    console.log('Geen wachtwoord opgegeven.');
    rl.close();
    process.exit(1);
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    console.log('\nJe gehashte wachtwoord:');
    console.log(hash);
    console.log('\nKopieer dit naar je .env bestand als ADMIN_PASS_HASH');
  } catch (error) {
    console.error('Fout bij hashen:', error);
  }

  rl.close();
});
