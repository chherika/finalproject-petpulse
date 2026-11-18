const mongoose = require('mongoose');

const dbConnect = async () => {
  if (!process.env.MONGO_URI) {
    console.error(JSON.stringify({ level: 'fatal', message: 'MONGO_URI is missing' }));
    process.exit(1);
  }
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
      maxPoolSize: 10
    });
    console.log(JSON.stringify({
      level: 'info',
      message: 'MongoDB Connected',
      host: conn.connection.host,
      db: conn.connection.name
    }));
  } catch (error) {
    console.error(JSON.stringify({ level: 'fatal', message: 'Database Connection Error', error: error.message }));
    process.exit(1);
  }
};

module.exports = dbConnect;