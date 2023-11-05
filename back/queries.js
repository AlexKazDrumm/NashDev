import pg from 'pg';
import moment from 'moment'
moment.locale('ru');
import { productionPoolOptions, secretKey } from './accesses.js';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';


const Pool = pg.Pool
const pool = new Pool(productionPoolOptions);

const SALT_ROUNDS = 10;

const isEmailValid = (email) => /^\S+@\S+\.\S+$/.test(email);

const isEmailExists = async (email) => {
    const { rows } = await pool.query('SELECT email FROM smbt_users WHERE email = $1', [email]);
    return rows.length > 0;
};

const isPhoneNumberValid = phone => /^(\+?[7-8] ?\(\d{3}\) ?|\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{2}[- ]?\d{2}$/.test(phone);

const isCertificateNumberValid = number => /^\d{2} \d{2} \d{2} \d{2}$/.test(number);

const hashPassword = async (password) => {
    return bcrypt.hash(password, SALT_ROUNDS);
}

const generateToken = (userId) => {
    return jwt.sign({ id: userId }, secretKey, { expiresIn: '1h' });
};

const saveFileAndRecord = async (file, table) => {
    let randomPostfix = (Math.floor(Math.random() * 1000000) + 1).toString();
    
    let currentDir = path.dirname(new URL(import.meta.url).pathname);
    if (process.platform === 'win32') {
        currentDir = currentDir.substr(1);
    }

    let targetPath = decodeURIComponent(path.join(currentDir, `./uploads/${randomPostfix}${path.extname(file.originalname)}`));
    
    await fs.promises.rename(file.path, targetPath);
    
    const result = await pool.query(`INSERT INTO ${table} (link) VALUES ($1) RETURNING id`, [targetPath]);
    return result.rows[0].id;
};

const register = async (request, response) => {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');
        const sertificate = request.files.sertificate[0];
        const insurance_contract = request.files.insurance_contract[0];
        const ward = request.files.ward[0];

        const {
            email, password, confirmPassword, fio, phone, role_id, status_id,
            sertificate_number, date_of_sert_issue,
            contract_number, date_of_cont_issue,
            ward_number, date_of_ward_issue, work_experience
        } = request.body;

        // Валидация email и телефона
        // if (!isEmailValid(email)) {
        //     throw new Error('Invalid email format.');
        // }
        const emailExists = await isEmailExists(email);
        if (emailExists) {
            throw new Error('Email already exists.');
        }
        // if (!isPhoneNumberValid(phone)) {
        //     throw new Error('Invalid phone number format.');
        // }

        if (password !== confirmPassword) {
            throw new Error('Passwords do not match.');
        }

        // if (!isCertificateNumberValid(sertificate_number) || 
        //     !isCertificateNumberValid(contract_number) || 
        //     !isCertificateNumberValid(ward_number)) {
        //     throw new Error('Invalid certificate or contract or ward number format.');
        // }

        const hashedPassword = await hashPassword(password);

        // Загрузка файлов и запись в базу данных
        const sertificateId = await saveFileAndRecord(sertificate, 'smbt_certificates');
        const insuranceContractId = await saveFileAndRecord(insurance_contract, 'smbt_insurance_contracts');
        const wardId = await saveFileAndRecord(ward, 'smbt_wards');

        // Запись данных в таблицу smbt_persons
        const personResult = await client.query(`
            INSERT INTO smbt_persons 
            (fio, phone, role_id, status_id, sertificate_id, sertificate_number, date_of_sert_issue, 
            insurance_contract_id, contract_number, date_of_cont_issue, 
            ward_id, ward_number, date_of_ward_issue, work_experience) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id`,
            [fio, phone, role_id, status_id, sertificateId, sertificate_number, date_of_sert_issue,
            insuranceContractId, contract_number, date_of_cont_issue,
            wardId, ward_number, date_of_ward_issue, work_experience]);

        const personId = personResult.rows[0].id;

        // Создание пользователя в smbt_users
        await client.query(`
            INSERT INTO smbt_users 
            (email, hashed_password, person_id) 
            VALUES ($1, $2, $3)`,
            [email, hashedPassword, personId]);

        await client.query('COMMIT');

        const token = generateToken(personId);

        const { rows } = await client.query(`
            SELECT * FROM smbt_persons WHERE id = $1
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
        const { rows } = await pool.query('SELECT id, hashed_password, person_id FROM smbt_users WHERE email = $1', [email]);
        
        if (rows.length === 0) {
            throw new Error('Пользователь с таким email не найден.');
        }

        const user = rows[0];

        const isPasswordCorrect = await bcrypt.compare(password, user.hashed_password);

        if (!isPasswordCorrect) {
            throw new Error('Неверный пароль.');
        }

        const token = generateToken(user.id);

        const { rows: personsRows } = await pool.query('SELECT * FROM smbt_persons WHERE id = $1', [user.person_id]);
        const personData = personsRows[0];

        response.status(200).json({ success: true, token, user: personData });

    } catch (error) {
        response.status(500).json({ success: false, message: error.message });
    }
}

export default {
    register,
    auth
}