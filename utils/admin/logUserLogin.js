import client from '../../config/databasepg.js'; // PostgreSQL pool configuration
import os from 'os';

const logUserLogin = async (user, loginTimestamp) => {
    try {
        const deviceInfo = {
            hostname: os.hostname(),
            platform: os.platform(),
            type: os.type(),
            username: os.userInfo().username,
        };

        const { username, ...restDeviceInfo } = deviceInfo;

        const insertLogQuery = `
            INSERT INTO userlogs (email, name, loginStatus, loginTime, deviceDetails, user_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING userlog_id
        `;
        const values = [user.email, user.username, 'Login', loginTimestamp, { username, ...restDeviceInfo }, user.user_id];
        const { rows } = await client.query(insertLogQuery, values);

    } catch (error) {
        console.error('Error logging user login:', error);
    }
};

export default logUserLogin;
