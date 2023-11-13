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
        const {
            email, password
        } = request.body;


        const emailExists = await isEmailExists(email);
        if (emailExists) {
            throw new Error('Email already exists.');
        }

        if (password !== confirmPassword) {
            throw new Error('Passwords do not match.');
        }

        const hashedPassword = await hashPassword(password);

        const personResult = await client.query(`
            INSERT INTO nd_renters 
            (email) 
            VALUES ($1) RETURNING id`,
            [email]);

        const personId = personResult.rows[0].id;

        // Создание пользователя в smbt_users
        await client.query(`
            INSERT INTO nd_users 
            (hashed_password, person_id) 
            VALUES ($1, $2)`,
            [hashedPassword, personId]);

        await client.query('COMMIT');

        const token = generateToken(personId);

        const { rows } = await client.query(`
            SELECT * FROM nd_renters WHERE id = $1
        `, [personId]);
        const userData = rows[0];

        response.status(200).json({ success: true, token, user: userData, message: "Registration successful" });

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
        const { rows } = await pool.query('SELECT u.id, u.hashed_password, p.email FROM nd_users u INNER JOIN nd_persons p ON u.person_id = p.id WHERE p.email = $1', [email]);
        
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

export default {
    register,
    auth
}