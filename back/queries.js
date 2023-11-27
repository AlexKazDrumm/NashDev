import pg from 'pg';
import moment from 'moment'
moment.locale('ru');
import { productionPoolOptions, secretKey } from './accesses.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';


const Pool = pg.Pool
const pool = new Pool(productionPoolOptions);

const SALT_ROUNDS = 10;

const isEmailExists = async (email) => {
    const { rows } = await pool.query('SELECT email FROM smbt_users WHERE email = $1', [email]);
    return rows.length > 0;
};

const hashPassword = async (password) => {
    return bcrypt.hash(password, SALT_ROUNDS);
}

const generateToken = (userId) => {
    return jwt.sign({ id: userId }, secretKey, { expiresIn: '1h' });
};

const register = async (request, response) => {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');
        const { email, password } = request.body;

        const emailExists = await isEmailExists(email);
        if (emailExists) {
            throw new Error('Email already exists.');
        }

        const hashedPassword = await hashPassword(password);

        // Создание записи в nd_persons
        const personResult = await client.query(`
            INSERT INTO nd_persons 
            (role_id) 
            VALUES (1) RETURNING id`
        );

        const personId = personResult.rows[0].id;

        // Создание пользователя в nd_users
        await client.query(`
            INSERT INTO nd_users 
            (email, hashed_password, person_id) 
            VALUES ($1, $2, $3)`,
            [email, hashedPassword, personId]
        );

        await client.query('COMMIT');

        const token = generateToken(personId);

        response.status(200).json({ success: true, token, message: "Registration successful" });

    } catch (error) {
        await client.query('ROLLBACK');
        response.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
}

const auth = async (request, response) => {
    const { email, password } = request.body;

    try {
        const { rows } = await pool.query(`
            SELECT u.id, u.hashed_password, u.person_id 
            FROM nd_users u 
            WHERE u.email = $1`, 
            [email]
        );
        
        if (rows.length === 0) {
            throw new Error('Пользователь с таким email не найден.');
        }

        const user = rows[0];

        const isPasswordCorrect = await bcrypt.compare(password, user.hashed_password);

        if (!isPasswordCorrect) {
            throw new Error('Неверный пароль.');
        }

        const token = generateToken(user.id);

        response.status(200).json({ success: true, token, user });

    } catch (error) {
        response.status(500).json({ success: false, message: error.message });
    }
}

const createRequest = async (request, response) => {
    const { token, phone, description } = request.body;
    
    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        await pool.query(`
            INSERT INTO nd_requests (description, phone, status_id, creator_id) 
            VALUES ($1, $2, 1, $3)`,
            [description, phone, userId]
        );

        response.status(201).json({ success: true, message: "Заявка успешно создана" });
    } catch (error) {
        console.error(error);
        response.status(500).json({ success: false, message: "Ошибка при создании заявки" });
    }
};

const getRequestsByCreator = async (request, response) => {
    const { token } = request.body;

    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const { rows } = await pool.query(`
            SELECT * FROM nd_requests WHERE creator_id = $1`,
            [userId]
        );

        response.status(200).json({ success: true, requests: rows });
    } catch (error) {
        console.error(error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка заявок" });
    }
};

const getRequestsByStatus = async (request, response) => {
    const { token, statusId } = request.body;

    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const { rows } = await pool.query(`
            SELECT * FROM nd_requests WHERE creator_id = $1 AND status_id = $2`,
            [userId, statusId]
        );

        response.status(200).json({ success: true, requests: rows });
    } catch (error) {
        console.error(error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка заявок по статусу" });
    }
};

export default {
    register,
    auth,
    createRequest,
    getRequestsByCreator,
    getRequestsByStatus
}