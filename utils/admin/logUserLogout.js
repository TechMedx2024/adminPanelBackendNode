// import client from '../../config/databasepg.js'; // PostgreSQL pool configuration
// import os from 'os';

// const logUserLogout = async (user, loginTimestamp) => {
//     console.log(user.user_id)
//     try {
//         const deviceInfo = {
//             hostname: os.hostname(),
//             platform: os.platform(),
//             type: os.type(),
//             username: os.userInfo().username,
//         };

//         const { username, ...restDeviceInfo } = deviceInfo;

//         const insertLogQuery = `
//             INSERT INTO userlogs (email, name, loginStatus, loginTime, deviceDetails, user_id)
//             VALUES ($1, $2, $3, $4, $5, $6)
//             RETURNING userlog_id
//         `;
//         const values = [user.email, user.name, 'Logout', loginTimestamp, { username, ...restDeviceInfo }, user.user_id];
//         const { rows } = await client.query(insertLogQuery, values);


//     } catch (error) {
//         console.error('Error logging user Logout:', error);
//     }
// };

// export default logUserLogout;


import client from '../../config/databasepg.js'; // PostgreSQL pool configuration
import os from 'os';

const logUserLogout = async (user, loginTimestamp) => {
    try {
        // Fetch user details from users table based on user_id
        const getUserQuery = `
            SELECT username, email FROM users WHERE user_id = $1
        `;
        const { rows: userRows } = await client.query(getUserQuery, [user.user_id]);

        if (userRows.length === 0) {
            console.error('User not found while logging logout');
            return;
        }

        const { username, email } = userRows[0];

        // Gather device information
        const deviceInfo = {
            hostname: os.hostname(),
            platform: os.platform(),
            type: os.type(),
            username: os.userInfo().username,
        };

        const { username: deviceUsername, ...restDeviceInfo } = deviceInfo;

        // Insert log into userlogs table
        const insertLogQuery = `
            INSERT INTO userlogs (email, name, loginStatus, loginTime, deviceDetails, user_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING userlog_id
        `;
        const values = [email, username, 'Logout', loginTimestamp, { username: deviceUsername, ...restDeviceInfo }, user.user_id];
        const { rows } = await client.query(insertLogQuery, values);

        console.log(`User logout logged successfully with log ID: ${rows[0].userlog_id}`);
    } catch (error) {
        console.error('Error logging user Logout:', error);
    }
};

export default logUserLogout;
