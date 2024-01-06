import pg from 'pg';
import moment from 'moment'
moment.locale('ru');
import { productionPoolOptions, secretKey } from './accesses.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';

const Pool = pg.Pool
const pool = new Pool(productionPoolOptions);

const SALT_ROUNDS = 10;

const isEmailExists = async (email) => {
    const { rows } = await pool.query('SELECT email FROM nd_users WHERE email = $1', [email]);
    return rows.length > 0;
};

const hashPassword = async (password) => {
    return bcrypt.hash(password, SALT_ROUNDS);
}

const generateToken = (userId) => {
    return jwt.sign({ id: userId }, secretKey, { expiresIn: '48h' });
};

const uploadDocument = async (avatarFile) => {
    let randomPostfix = (Math.floor(Math.random() * 1000000) + 1).toString();

    let currentDir = path.dirname(new URL(import.meta.url).pathname);
    if (process.platform === 'win32') {
        currentDir = currentDir.substr(1);
    }

    let fileName = `${randomPostfix}${path.extname(avatarFile.originalname)}`;
    let avatarPath = decodeURIComponent(path.join(currentDir, './uploads', fileName));

    if (!fs.existsSync(path.join(currentDir, './uploads'))) {
        await fs.promises.mkdir(path.join(currentDir, './uploads'), { recursive: true });
    }

    await fs.promises.rename(avatarFile.path, avatarPath);

    return fileName;
};

const register = async (request, response) => {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');
        const { name, email, password, role_id } = request.body;

        const emailExists = await isEmailExists(email);
        if (emailExists) {
            throw new Error('Email already exists.');
        }

        const hashedPassword = await hashPassword(password);

        // Создание записи в nd_persons
        const personResult = await client.query(`
            INSERT INTO nd_persons (name, role_id) 
            VALUES ($1, $2) RETURNING id`,
            [name, role_id]
        );

        const personId = personResult.rows[0].id;

        // Создание пользователя в nd_users
        const userResult = await client.query(`
            INSERT INTO nd_users (email, hashed_password, person_id) 
            VALUES ($1, $2, $3) RETURNING id`,
            [email, hashedPassword, personId]
        );

        const userId = userResult.rows[0].id;

        await client.query(`
            INSERT INTO nd_tips (user_id) 
            VALUES ($1)`, // Дополнительные поля в зависимости от структуры вашей таблицы
            [userId]
        );

        const tipsResult = await client.query(`
            SELECT * FROM nd_tips 
            WHERE user_id = $1`, 
            [userId]
        );
        const tips = tipsResult.rows;

        await client.query('COMMIT');

        // Получение полных данных о пользователе
        const userInfo = await client.query(`
            SELECT p.id AS person_id, p.name, p.role_id, u.id AS user_id, u.email 
            FROM nd_persons p 
            JOIN nd_users u ON p.id = u.person_id 
            WHERE u.id = $1`,
            [userId]
        );

        const user = userInfo.rows[0];
        const token = generateToken(user.user_id);

        const resultUser = {
            ...user,
            tips: tips, // Собираем все подсказки пользователя
        };

        response.status(200).json({
            success: true,
            token,
            user: resultUser,
            message: "Registration successful"
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error in createRequest:', error);
        response.status(500).json({ success: false, message: "Ошибка при создании заявки" });
    } finally {
        client.release();
    }
};

const auth = async (request, response) => {
    const { email, password } = request.body;
    let client;

    try {
        client = await pool.connect();

        const userResult = await client.query(`
            SELECT u.id AS user_id, u.hashed_password, u.person_id 
            FROM nd_users u 
            WHERE u.email = $1`,
            [email]
        );
        
        if (userResult.rows.length === 0) {
            throw new Error('Пользователь с таким email не найден.');
        }

        const user = userResult.rows[0];
        const isPasswordCorrect = await bcrypt.compare(password, user.hashed_password);

        if (!isPasswordCorrect) {
            throw new Error('Неверный пароль.');
        }

        // Получение полных данных о пользователе
        const userInfo = await client.query(`
            SELECT p.id AS person_id, p.name, p.role_id, u.id AS user_id, u.email 
            FROM nd_persons p 
            JOIN nd_users u ON p.id = u.person_id 
            WHERE u.id = $1`,
            [user.user_id]
        );

        const userDetails = userInfo.rows[0];

        // Получение подсказок пользователя
        const tipsResult = await client.query(`
            SELECT * FROM nd_tips 
            WHERE user_id = $1`, 
            [user.user_id]
        );

        const tips = tipsResult.rows;

        const token = generateToken(userDetails.user_id);

        const resultUser = {
            ...userDetails,
            tips: tips  // Собираем все подсказки пользователя
        };

        response.status(200).json({
            success: true,
            token,
            user: resultUser
        });

    } catch (error) {
        response.status(500).json({ success: false, message: error.message });
    } finally {
        if (client) {
            client.release();
        }
    }
}

const createRequest = async (request, response) => {
    const client = await pool.connect();
    try {
        // Получаем токен из заголовка Authorization

        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;
        const { phone, description, categoryIds, title } = request.body;

        console.log({ phone, description, categoryIds, title })

        let categoryIdsArray;
        try {
            // Попытка преобразовать categoryIds из строки в массив JavaScript
            categoryIdsArray = JSON.parse(request.body.categoryIds);
        } catch (error) {
            // Если преобразование не удалось, отправляем ошибку
            return response.status(400).json({ success: false, message: "Невозможно преобразовать categoryIds в массив" });
        }

        if (!Array.isArray(categoryIdsArray)) {
            return response.status(400).json({ success: false, message: "categoryIds должен быть массивом" });
        }

        await client.query('BEGIN');

        // Вставляем заявку в nd_requests
        const requestResult = await client.query(`
            INSERT INTO nd_requests (description, phone, status_id, creator_id, title) 
            VALUES ($1, $2, 1, $3, $4) RETURNING *`, // Возвращаем все данные о заявке
            [description, phone, userId, title]
        );
        const requestInfo = requestResult.rows[0];

        // Для каждой категории из списка вставляем запись в nd_request_category_middleware
        for (const categoryId of categoryIdsArray) {
            await client.query(`
                INSERT INTO nd_request_category_middleware (request_id, category_id) 
                VALUES ($1, $2);`,
                [requestInfo.id, categoryId]
            );
        }

        // Получаем полные данные о категориях
        const categoriesQuery = `
            SELECT c.id, c.title 
            FROM nd_request_categories c 
            WHERE c.id = ANY($1)`;
        const categoriesResult = await client.query(categoriesQuery, [categoryIdsArray]);
        const categories = categoriesResult.rows;

        const files = request.files;  // предполагается, что файлы приходят в `request.files`
        let uploadedFiles = [];
        if (request.files && request.files.length > 0) {  // Проверяем, пришли ли файлы
            for (const file of request.files) {
                const fileName = await uploadDocument(file);
                const fileInsertResult = await client.query(`
                    INSERT INTO nd_request_files (request_id, file) 
                    VALUES ($1, $2) RETURNING *;`,
                    [requestInfo.id, fileName]
                );
                uploadedFiles.push(fileInsertResult.rows[0]);
            }
        }

        await client.query('COMMIT');

        response.status(201).json({
            success: true,
            message: "Заявка успешно создана",
            request: requestInfo,
            categories: categories, // Возвращаем полные данные о категориях
            files: uploadedFiles  // Возвращаем информацию о загруженных файлах
        });
    } catch (error) {
        console.error(error);
        await client.query('ROLLBACK');
        
        response.status(500).json({ success: false, message: "Ошибка при создании заявки" });
    } finally {
        client.release();
    }
};

const getRequestsByCreator = async (request, response) => {
    const client = await pool.connect();
    try {
        console.log('Получение заголовка авторизации');
        const authHeader = request.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];

        if (token == null) {
            console.error('Токен не предоставлен');
            return response.status(401).json({ success: false, message: "Токен не предоставлен" });
        }

        console.log('Декодирование токена');
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        console.log(`Запрос данных заявок для пользователя ${userId}`);
        const requestsResult = await client.query(`
            SELECT * FROM nd_requests WHERE creator_id = $1`,
            [userId]
        );
        const requests = requestsResult.rows;

        for (let request of requests) {
            console.log(`Обработка заявки с ID ${request.id}`);

            try {
                const categoriesResult = await client.query(`
                    SELECT * FROM nd_request_category_middleware 
                    WHERE request_id = $1`,
                    [request.id]
                );
                request.categories = categoriesResult.rows;
            } catch (err) {
                console.error(`Ошибка при получении категорий для заявки ${request.id}:`, err);
                throw err;
            }

            try {
                const filesResult = await client.query(`
                    SELECT * FROM nd_request_files 
                    WHERE request_id = $1`,
                    [request.id]
                );
                request.files = filesResult.rows;
            } catch (err) {
                console.error(`Ошибка при получении файлов для заявки ${request.id}:`, err);
                throw err;
            }
        }

        console.log('Отправка данных заявок');
        response.status(200).json({ success: true, requests });
    } catch (error) {
        console.error('Глобальная ошибка обработки:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка заявок" });
    } finally {
        console.log('Освобождение клиента');
        client.release();
    }
};

const getRequestsByStatus = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const { statusId } = request.body;

        const requestsResult = await client.query(`
            SELECT * FROM nd_requests WHERE creator_id = $1 AND status_id = $2`,
            [userId, statusId]
        );
        const requests = requestsResult.rows;

        for (let request of requests) {
            const categoriesResult = await client.query(`
                SELECT * FROM nd_request_category_middleware 
                WHERE request_id = $1`,
                [request.id]
            );
            request.categories = categoriesResult.rows;
        }

        response.status(200).json({ success: true, requests });
    } catch (error) {
        console.error(error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка заявок по статусу" });
    } finally {
        client.release();
    }
};

const getAllRequestCategories = async (request, response) => {
    try {
        const { rows } = await pool.query('SELECT * FROM nd_request_categories');
        response.status(200).json({ success: true, categories: rows });
    } catch (error) {
        console.error(error);
        response.status(500).json({ success: false, message: "Ошибка при получении категорий заявок" });
    }
};

const hideUserTip = async (request, response) => {
    const client = await pool.connect();
    try {
        // Извлекаем токен из заголовка Authorization
        const token = request.headers.authorization.split(' ')[1];

        // Извлекаем заголовок подсказки из тела запроса
        const { tipTitle } = request.body;

        // Допустимые заголовки подсказок
        const validTipTitles = ['my_orders', 'profile', 'support', 'request_status', 'order_payment', 'manager'];

        // Проверяем, является ли переданный заголовок допустимым
        if (!validTipTitles.includes(tipTitle)) {
            throw new Error('Недопустимый заголовок подсказки.');
        }

        // Декодируем токен и получаем id пользователя
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        // Формируем имя столбца для обновления
        const columnName = tipTitle;

        // Обновляем значение подсказки для пользователя
        const query = `
            UPDATE nd_tips 
            SET "${columnName}" = false 
            WHERE user_id = $1
        `;

        await client.query(query, [userId]);

        response.status(200).json({
            success: true,
            message: `Подсказка "${columnName}" успешно скрыта для пользователя.`,
        });

    } catch (error) {
        response.status(500).json({ success: false, message: error.message });
    } finally {
        if (client) {
            client.release();
        }
    }
}

const deleteRequestFile = async (request, response) => {
    const client = await pool.connect();
    try {
        // Извлекаем токен и ID файла из запроса
        const token = request.headers.authorization.split(' ')[1];
        const { fileId } = request.body;

        // Декодируем токен и получаем ID пользователя
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        await client.query('BEGIN');

        // Находим файл и соответствующую заявку
        const fileResult = await client.query(`
            SELECT r.creator_id, f.file
            FROM nd_request_files f
            JOIN nd_requests r ON f.request_id = r.id
            WHERE f.id = $1`, 
            [fileId]
        );

        if (fileResult.rows.length === 0) {
            throw new Error('Файл не найден.');
        }

        const file = fileResult.rows[0];

        // Проверяем, принадлежит ли файл заявке текущего пользователя
        if (file.creator_id !== userId) {
            throw new Error('У вас нет прав на удаление этого файла.');
        }

        // Удаляем файл из файловой системы
        let currentDir = path.dirname(new URL(import.meta.url).pathname);
        if (process.platform === 'win32') {
            currentDir = currentDir.substr(1);
        }
        const filePath = path.join(currentDir, './uploads', file.file);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        // Удаляем запись о файле из базы данных
        await client.query(`
            DELETE FROM nd_request_files 
            WHERE id = $1`, 
            [fileId]
        );

        await client.query('COMMIT');

        response.status(200).json({
            success: true,
            message: "Файл успешно удален"
        });
    } catch (error) {
        await client.query('ROLLBACK');
        response.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
};

const updateRequest = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;
        const { requestId, phone, description, title, categoryIds } = request.body;

        let categoryIdsArray;
        try {
            categoryIdsArray = JSON.parse(categoryIds);
        } catch (error) {
            return response.status(400).json({ success: false, message: "Невозможно преобразовать categoryIds в массив" });
        }

        if (!Array.isArray(categoryIdsArray)) {
            return response.status(400).json({ success: false, message: "categoryIds должен быть массивом" });
        }

        await client.query('BEGIN');

        // Проверяем, принадлежит ли заявка пользователю
        const requestOwnerResult = await client.query(`
            SELECT id FROM nd_requests 
            WHERE id = $1 AND creator_id = $2`, 
            [requestId, userId]
        );

        if (requestOwnerResult.rows.length === 0) {
            throw new Error('У вас нет прав на редактирование этой заявки.');
        }

        // Формируем строку запроса на обновление с учетом предоставленных полей
        let updateQuery = 'UPDATE nd_requests SET ';
        let updateValues = [];
        let counter = 1;

        if (description !== undefined) {
            updateQuery += `description = $${counter}, `;
            updateValues.push(description);
            counter++;
        }

        if (phone !== undefined) {
            updateQuery += `phone = $${counter}, `;
            updateValues.push(phone);
            counter++;
        }

        // Добавляем условие для обновления заголовка, если он предоставлен
        if (title !== undefined) {
            updateQuery += `title = $${counter}, `;
            updateValues.push(title);
            counter++;
        }

        // Удаляем последнюю запятую и добавляем условие WHERE
        updateQuery = updateQuery.slice(0, -2) + ` WHERE id = $${counter}`;
        updateValues.push(requestId);

        if (updateValues.length > 1) { // Проверяем, есть ли поля для обновления
            await client.query(updateQuery, updateValues);
        }

        // Обновляем категории заявки
        await client.query(`
            DELETE FROM nd_request_category_middleware 
            WHERE request_id = $1`, 
            [requestId]
        );

        for (const categoryId of categoryIdsArray) {
            await client.query(`
                INSERT INTO nd_request_category_middleware (request_id, category_id) 
                VALUES ($1, $2)`,
                [requestId, categoryId]
            );
        }

        await client.query('COMMIT');

        response.status(200).json({
            success: true,
            message: "Заявка успешно обновлена"
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error(error);
        response.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
};

const cancelRequest = async (request, response) => {
    const client = await pool.connect();
    try {
        // Извлекаем токен и данные из запроса
        const token = request.headers.authorization.split(' ')[1];
        const { requestId, cancelCause } = request.body;

        // Декодируем токен и получаем ID пользователя
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        await client.query('BEGIN');

        // Проверяем, принадлежит ли заявка пользователю и не отменена ли она уже
        const requestResult = await client.query(`
            SELECT * FROM nd_requests 
            WHERE id = $1 AND creator_id = $2 AND is_canceled = false`,
            [requestId, userId]
        );

        if (requestResult.rows.length === 0) {
            throw new Error('Заявка не найдена, не принадлежит вам или уже отменена.');
        }

        // Обновляем статус и причину отмены заказа
        await client.query(`
            UPDATE nd_requests 
            SET is_canceled = true, cancel_cause = $1
            WHERE id = $2`,
            [cancelCause, requestId]
        );

        await client.query('COMMIT');

        response.status(200).json({
            success: true,
            message: "Заявка успешно отменена"
        });
    } catch (error) {
        await client.query('ROLLBACK');
        response.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
};

const getAllRequests = async (request, response) => {
    const client = await pool.connect();
    try {
        console.log('Запрос всех данных заявок');
        const requestsResult = await client.query(`
            SELECT * FROM nd_requests`);
        const requests = requestsResult.rows;

        for (let request of requests) {
            console.log(`Обработка заявки с ID ${request.id}`);

            try {
                const categoriesResult = await client.query(`
                    SELECT * FROM nd_request_category_middleware 
                    WHERE request_id = $1`,
                    [request.id]
                );
                request.categories = categoriesResult.rows;
            } catch (err) {
                console.error(`Ошибка при получении категорий для заявки ${request.id}:`, err);
                throw err;
            }

            try {
                const filesResult = await client.query(`
                    SELECT * FROM nd_request_files 
                    WHERE request_id = $1`,
                    [request.id]
                );
                request.files = filesResult.rows;
            } catch (err) {
                console.error(`Ошибка при получении файлов для заявки ${request.id}:`, err);
                throw err;
            }
        }

        console.log('Отправка данных всех заявок');
        response.status(200).json({ success: true, requests });
    } catch (error) {
        console.error('Глобальная ошибка обработки:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка всех заявок" });
    } finally {
        console.log('Освобождение клиента');
        client.release();
    }
};

const submitApplication = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;
        const requestId = request.body.requestId;

        await client.query(`
            INSERT INTO nd_applications (performer_id, request_id)
            VALUES ($1, $2)`,
            [userId, requestId]
        );

        console.log('Заявка на выполнение проекта отправлена');
        response.status(200).json({ success: true, message: "Заявка отправлена" });
    } catch (error) {
        console.error('Ошибка при отправке заявки:', error);
        response.status(500).json({ success: false, message: "Ошибка при отправке заявки" });
    } finally {
        client.release();
    }
};

const getApplicationResponses = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;
        const requestId = request.body.requestId;
        console.log(requestId, userId)
        const creatorResult = await client.query(`
            SELECT creator_id FROM nd_requests WHERE id = $1`,
            [requestId]
        );

        if (creatorResult.rows[0].creator_id !== userId) {
            return response.status(403).json({ success: false, message: "Нет доступа" });
        }

        const applicationsResult = await client.query(`
            SELECT a.*, p.* FROM nd_applications a 
            JOIN nd_persons p ON a.performer_id = p.id 
            WHERE a.request_id = $1`,
            [requestId]
        );

        console.log('Список откликов получен');
        response.status(200).json({ success: true, applications: applicationsResult.rows });
    } catch (error) {
        console.error('Ошибка при получении откликов:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении откликов" });
    } finally {
        client.release();
    }
};

const respondToApplication = async (request, response) => {
    const client = await pool.connect();
    try {
        const applicationId = request.body.applicationId;
        const confirm = request.body.confirm;

        if (confirm) {
            await client.query(`
                UPDATE nd_applications SET is_approved = true WHERE id = $1`,
                [applicationId]
            );

            const applicationInfo = await client.query(`
                SELECT performer_id, request_id FROM nd_applications WHERE id = $1`,
                [applicationId]
            );

            await client.query(`
                INSERT INTO nd_performer_request_middleware (performer_id, request_id)
                VALUES ($1, $2)`,
                [applicationInfo.rows[0].performer_id, applicationInfo.rows[0].request_id]
            );
        } else {
            await client.query(`
                UPDATE nd_applications SET is_rejected = true WHERE id = $1`,
                [applicationId]
            );
        }

        console.log('Ответ на заявку обработан');
        response.status(200).json({ success: true, message: "Ответ на заявку обработан" });
    } catch (error) {
        console.error('Ошибка при ответе на заявку:', error);
        response.status(500).json({ success: false, message: "Ошибка при ответе на заявку" });
    } finally {
        client.release();
    }
};

const getMyApplications = async (request, response) => {
    const client = await pool.connect();
    try {
        const token = request.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.id;

        const applicationsResult = await client.query(`
            SELECT * FROM nd_applications WHERE performer_id = $1`,
            [userId]
        );

        console.log('Список заявок получен');
        response.status(200).json({ success: true, applications: applicationsResult.rows });
    } catch (error) {
        console.error('Ошибка при получении списка заявок:', error);
        response.status(500).json({ success: false, message: "Ошибка при получении списка заявок" });
    } finally {
        client.release();
    }
};

export default {
    register,
    auth,
    createRequest,
    getRequestsByCreator,
    getRequestsByStatus,
    getAllRequestCategories,
    hideUserTip,
    deleteRequestFile,
    updateRequest,
    cancelRequest,
    getAllRequests,
    submitApplication,
    getApplicationResponses,
    respondToApplication,
    getMyApplications
}