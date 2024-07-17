import pg from 'pg';

const { Client } = pg;
const client = new Client({
    host: "localhost",
    user: "postgres",
    port: 65535,
    password: "medx",
    database: "medx"
});

async function connectDB() {
    try {
        await client.connect();
        console.log('Connected to PostgreSQL');
    } catch (error) {
        console.error('Error connecting to PostgreSQL:', error.message);
        throw error; // Rethrow the error to handle it elsewhere if needed
    }
}

// Call connectDB to establish the connection
connectDB().catch(err => console.error('Error in connectDB:', err));

export default client;
